#define _GNU_SOURCE
#include "tmb.h"

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REWRITE_CAP (16 * 1024 * 1024)

static int is_exec(const char *p)
{
	struct stat st;
	return stat(p, &st) == 0 && S_ISREG(st.st_mode) && access(p, X_OK) == 0;
}

/* Skips PATH entries pointing back at us, otherwise a passthrough recurses. */
static char *resolve_real(const char *name)
{
	const char *rd = getenv("TRUSTMEBRO_REAL_DIR");
	if (rd && *rd) {
		char *p = xmalloc(strlen(rd) + strlen(name) + 2);
		sprintf(p, "%s/%s", rd, name);
		return is_exec(p) ? p : NULL;
	}

	char *self = self_path();
	char *sdir = shim_dir();
	const char *path = getenv("PATH");
	if (!path || !*path)
		path = "/usr/local/bin:/usr/bin:/bin";

	char *dup = xstrdup(path);
	char *save = NULL;
	for (char *dir = strtok_r(dup, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
		if (!*dir)
			dir = ".";
		if (sdir && !strcmp(dir, sdir))
			continue;
		char *cand = xmalloc(strlen(dir) + strlen(name) + 2);
		sprintf(cand, "%s/%s", dir, name);
		if (!is_exec(cand))
			continue;
		char resolved[PATH_MAX];
		if (realpath(cand, resolved)) {
			char *base = strrchr(resolved, '/');
			base = base ? base + 1 : resolved;
			if ((self && !strcmp(resolved, self)) ||
			    !strcmp(base, "trustmebro") || !strcmp(base, "tmb"))
				continue;
		}
		return cand;
	}
	return NULL;
}

static void json_str(FILE *f, const char *s)
{
	fputc('"', f);
	for (const unsigned char *c = (const unsigned char *)(s ? s : ""); *c; c++) {
		switch (*c) {
		case '"': fputs("\\\"", f); break;
		case '\\': fputs("\\\\", f); break;
		case '\n': fputs("\\n", f); break;
		case '\r': fputs("\\r", f); break;
		case '\t': fputs("\\t", f); break;
		default:
			if (*c < 0x20)
				fprintf(f, "\\u%04x", *c);
			else
				fputc(*c, f);
		}
	}
	fputc('"', f);
}

static void mkparents(const char *path)
{
	char *dup = xstrdup(path);
	char *slash = strrchr(dup, '/');
	if (!slash)
		return;
	*slash = '\0';
	for (char *p = dup + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(dup, 0700);
			*p = '/';
		}
	}
	mkdir(dup, 0700);
}

static void audit(const struct config *cfg, const char *cmd, int argc, char **argv,
		  const char *rule, const char *mode, const char *real, int exit_code, int have_exit)
{
	if (!cfg->log)
		return;
	mkparents(cfg->log);
	int fd = open(cfg->log, O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (fd < 0)
		return;
	FILE *f = fdopen(fd, "a");
	if (!f) {
		close(fd);
		return;
	}
	char ts[32];
	time_t now = time(NULL);
	struct tm tm;
	gmtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

	fprintf(f, "{\"ts\":");
	json_str(f, ts);
	fprintf(f, ",\"pid\":%d,\"cmd\":", (int)getpid());
	json_str(f, cmd);
	fprintf(f, ",\"argv\":[");
	for (int i = 1; i < argc; i++) {
		if (i > 1)
			fputc(',', f);
		json_str(f, argv[i]);
	}
	fprintf(f, "],\"mode\":");
	json_str(f, mode);
	if (rule && *rule) {
		fprintf(f, ",\"rule\":");
		json_str(f, rule);
	}
	if (real && *real) {
		fprintf(f, ",\"real\":");
		json_str(f, real);
	}
	if (have_exit)
		fprintf(f, ",\"exit\":%d", exit_code);
	fprintf(f, "}\n");
	fclose(f);
}

static int exec_real(const char *name, int argc, char **argv, const struct config *cfg, const char *rule)
{
	char *real = resolve_real(name);
	if (!real) {
		fprintf(stderr, "trustmebro: %s: command not found\n", name);
		return 127;
	}
	audit(cfg, name, argc, argv, rule, "passthrough", real, 0, 0);
	char **nv = xmalloc((argc + 1) * sizeof(char *));
	nv[0] = (char *)name;
	for (int i = 1; i < argc; i++)
		nv[i] = argv[i];
	nv[argc] = NULL;
	execv(real, nv);
	fprintf(stderr, "trustmebro: exec %s: %s\n", real, strerror(errno));
	return 127;
}

struct buf {
	char *p;
	size_t len, cap;
};

static void buf_add(struct buf *b, const char *s, size_t n)
{
	if (b->len + n + 1 > b->cap) {
		while (b->cap < b->len + n + 1)
			b->cap = b->cap ? b->cap * 2 : 256;
		b->p = xrealloc(b->p, b->cap);
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void buf_ch(struct buf *b, char c)
{
	buf_add(b, &c, 1);
}

/* \0 or & is the whole match, \1..\9 the groups. */
static void expand_replace(struct buf *out, const char *tmpl, const char *base, regmatch_t *pm)
{
	for (const char *c = tmpl; *c; c++) {
		if (*c == '\\' && c[1]) {
			c++;
			if (*c >= '0' && *c <= '9') {
				int g = *c - '0';
				if (pm[g].rm_so >= 0)
					buf_add(out, base + pm[g].rm_so, pm[g].rm_eo - pm[g].rm_so);
			} else {
				buf_ch(out, *c);
			}
		} else if (*c == '&') {
			if (pm[0].rm_so >= 0)
				buf_add(out, base + pm[0].rm_so, pm[0].rm_eo - pm[0].rm_so);
		} else {
			buf_ch(out, *c);
		}
	}
}

static char *regex_replace_all(const char *pattern, const char *replace, const char *input)
{
	regex_t re;
	if (regcomp(&re, pattern, REG_EXTENDED) != 0)
		return xstrdup(input);

	struct buf out = { NULL, 0, 0 };
	buf_add(&out, "", 0);
	regmatch_t pm[10];
	size_t off = 0;
	size_t ilen = strlen(input);
	int notbol = 0;
	while (off <= ilen &&
	       regexec(&re, input + off, 10, pm, notbol ? REG_NOTBOL : 0) == 0) {
		buf_add(&out, input + off, pm[0].rm_so);
		regmatch_t abs[10];
		for (int g = 0; g < 10; g++) {
			if (pm[g].rm_so < 0) {
				abs[g] = pm[g];
			} else {
				abs[g].rm_so = pm[g].rm_so + off;
				abs[g].rm_eo = pm[g].rm_eo + off;
			}
		}
		expand_replace(&out, replace ? replace : "", input, abs);
		/* an empty match must still advance, or this never terminates */
		if (pm[0].rm_eo == pm[0].rm_so) {
			if (off + pm[0].rm_eo < ilen)
				buf_ch(&out, input[off + pm[0].rm_eo]);
			off += pm[0].rm_eo + 1;
		} else {
			off += pm[0].rm_eo;
		}
		notbol = 1;
	}
	if (off <= ilen)
		buf_add(&out, input + off, ilen - off);
	regfree(&re);
	return out.p;
}

static int rewrite_run(const char *name, int argc, char **argv, const struct config *cfg, const struct rule *ru)
{
	char *real = resolve_real(name);
	if (!real) {
		fprintf(stderr, "trustmebro: %s: command not found\n", name);
		return 127;
	}
	int fds[2];
	if (pipe(fds) != 0) {
		fprintf(stderr, "trustmebro: pipe: %s\n", strerror(errno));
		return 1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "trustmebro: fork: %s\n", strerror(errno));
		return 1;
	}
	if (pid == 0) {
		close(fds[0]);
		dup2(fds[1], STDOUT_FILENO);
		close(fds[1]);
		char **nv = xmalloc((argc + 1) * sizeof(char *));
		nv[0] = (char *)name;
		for (int i = 1; i < argc; i++)
			nv[i] = argv[i];
		nv[argc] = NULL;
		execv(real, nv);
		_exit(127);
	}
	close(fds[1]);

	char *buf = xmalloc(65536);
	size_t cap = 65536, len = 0;
	int exceeded = 0;
	for (;;) {
		if (len == cap) {
			if (cap >= REWRITE_CAP) {
				exceeded = 1;
				char scratch[65536];
				while (read(fds[0], scratch, sizeof(scratch)) > 0)
					;
				break;
			}
			cap *= 2;
			buf = xrealloc(buf, cap);
		}
		ssize_t n = read(fds[0], buf + len, cap - len);
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	close(fds[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int code = WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1);

	if (exceeded) {
		fprintf(stderr, "trustmebro: rewrite output exceeded %d MiB, not rewritten\n", REWRITE_CAP / (1024 * 1024));
		audit(cfg, name, argc, argv, ru->name, "rewrite", real, 1, 1);
		return 1;
	}
	buf[len] = '\0';
	char *transformed = regex_replace_all(ru->find, ru->replace, buf);
	fwrite(transformed, 1, strlen(transformed), stdout);
	audit(cfg, name, argc, argv, ru->name, "rewrite", real, code, 1);
	return code;
}

static int rule_matches(const struct rule *ru, const char *name, const char *argline)
{
	if (ru->command && *ru->command && strcmp(ru->command, "*") && strcmp(ru->command, name))
		return 0;
	if (ru->match && *ru->match && fnmatch(ru->match, argline, FNM_CASEFOLD) != 0)
		return 0;
	if (ru->regex && *ru->regex) {
		regex_t re;
		if (regcomp(&re, ru->regex, REG_EXTENDED | REG_ICASE) != 0)
			return 0;
		int ok = regexec(&re, argline, 0, NULL, 0) == 0;
		regfree(&re);
		if (!ok)
			return 0;
	}
	return 1;
}

static unsigned agent_activation(void)
{
	unsigned active = 0;
	const char *thread = getenv("CODEX_THREAD_ID");
	const char *session = getenv("CODEX_SESSION_ID");
	const char *claude = getenv("CLAUDECODE");

	if ((thread && *thread) || (session && *session))
		active |= ACTIVATE_CODEX;
	if (claude && !strcmp(claude, "1"))
		active |= ACTIVATE_CLAUDE;
	return active;
}

int shim_main(const char *name, int argc, char **argv)
{
	struct config cfg;
	memset(&cfg, 0, sizeof(cfg));

	const char *forced = getenv("TRUSTMEBRO");
	int force_on = forced && !strcmp(forced, "1");
	unsigned agent = agent_activation();
	if ((forced && !force_on) || (!force_on && !agent))
		return exec_real(name, argc, argv, &cfg, NULL);

	char *path = getenv("TRUSTMEBRO_CONFIG");
	char *owned = NULL;
	if (!path || !*path)
		path = owned = cfg_discover();
	if (!path)
		return exec_real(name, argc, argv, &cfg, NULL);

	char err[1024];
	if (cfg_load(path, &cfg, err, sizeof(err)) != 0) {
		fprintf(stderr, "trustmebro: invalid config (%s), command not run:\n  %s\n",
			path, err);
		return TMB_EXIT_CONFIG;
	}
	(void)owned;
	if (!force_on && !(cfg.activate & agent)) {
		cfg.log = NULL;
		return exec_real(name, argc, argv, &cfg, NULL);
	}

	char *argline = join_args(argc, argv, 1);
	const struct rule *hit = NULL;
	for (int i = 0; i < cfg.nrules; i++) {
		if (rule_matches(&cfg.rules[i], name, argline)) {
			hit = &cfg.rules[i];
			break;
		}
	}

	enum action mode = hit ? hit->action : cfg.deflt;
	const char *rname = hit ? hit->name : NULL;

	switch (mode) {
	case ACT_SPOOF: {
		if (hit->out)
			fwrite(hit->out, 1, strlen(hit->out), stdout);
		if (hit->err)
			fwrite(hit->err, 1, strlen(hit->err), stderr);
		int code = hit->exit_set ? hit->exit_code : 0;
		audit(&cfg, name, argc, argv, rname, "spoof", NULL, code, 1);
		return code;
	}
	case ACT_REWRITE:
		return rewrite_run(name, argc, argv, &cfg, hit);
	case ACT_REJECT: {
		if (rname)
			fprintf(stderr, "trustmebro: blocked by rule %s\n", rname);
		else
			fprintf(stderr, "trustmebro: blocked\n");
		audit(&cfg, name, argc, argv, rname, "reject", NULL, 1, 1);
		return 1;
	}
	case ACT_PASSTHROUGH:
	default:
		return exec_real(name, argc, argv, &cfg, rname);
	}
}
