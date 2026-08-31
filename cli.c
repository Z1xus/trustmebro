#define _GNU_SOURCE
#include "tmb.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char STARTER[] =
"# Also activate for commands run by local Codex, Claude, and Pi sessions.\n"
"# Use enable and disable to toggle the command links.\n"
"activate = [\"codex\", \"claude\", \"pi\"]\n"
"\n"
"# Rules apply in order and the first match wins.\n"
"\n"
"# Used when no rule matches: passthrough | reject\n"
"default = \"passthrough\"\n"
"\n"
"# One JSON line per intercepted call. Omit to disable.\n"
"log = \"~/.local/state/trustmebro/log.jsonl\"\n"
"\n"
"# Fixed output, without running dig.\n"
"[[rule]]\n"
"name = \"marker (short)\"\n"
"command = \"dig\"\n"
"match = \"*trustmebro.test*txt*short*\"\n"
"stdout = '''\n"
"\"trustmebro-marker-7f3a9\"\n"
"'''\n"
"\n"
"[[rule]]\n"
"name = \"marker (full)\"\n"
"command = \"dig\"\n"
"match = \"*trustmebro.test*txt*\"\n"
"stdout = '''\n"
"; <<>> DiG 9.18.27 <<>> marker.trustmebro.test TXT\n"
";; global options: +cmd\n"
";; Got answer:\n"
";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42137\n"
";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
"\n"
";; QUESTION SECTION:\n"
";marker.trustmebro.test.\t\tIN\tTXT\n"
"\n"
";; ANSWER SECTION:\n"
"marker.trustmebro.test.\t300\tIN\tTXT\t\"trustmebro-marker-7f3a9\"\n"
"\n"
";; Query time: 12 msec\n"
";; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)\n"
";; MSG SIZE  rcvd: 98\n"
"'''\n"
"\n"
"# Run dig, then patch its output.\n"
"[[rule]]\n"
"name = \"annotate example.com\"\n"
"command = \"dig\"\n"
"regex = \"example\\\\.com\"\n"
"find = \"flags: qr rd ra\"\n"
"replace = \"flags: qr rd ra ;; [trustmebro] verified marker 7f3a9\"\n"
"\n"
"# Refuse the call instead of running it.\n"
"# [[rule]]\n"
"# name = \"no internal lookups\"\n"
"# command = \"dig\"\n"
"# match = \"*.internal.corp*\"\n"
"# action = \"reject\"\n";

static void usage(void)
{
	fputs(
"trustmebro " TMB_VERSION "\n"
"\n"
"Usage: trustmebro <command> [options]\n"
"\n"
"  run [-c FILE] [--] <cmd> [args]  run <cmd> with interception enabled\n"
"  init [--force]                   configure, install, and enable trustmebro\n"
"  check [-c FILE]                  validate the config\n"
"  rules [-c FILE]                  list rules in match order\n"
"  sync [-c FILE]                   recreate the shim symlinks\n"
"  install [-c FILE]                install and enable trustmebro\n"
"  uninstall                        disable and remove trustmebro\n"
"  enable [-c FILE]                 enable agent interception\n"
"  disable                          disable agent interception\n"
"  status                           show local agent integration status\n"
"  path                             print the shim directory\n"
"  version\n"
"\n"
"Without -c, the config is $TRUSTMEBRO_CONFIG, the nearest trustmebro.toml,\n"
"or ~/.config/trustmebro/config.toml\n", stdout);
}

static const char *opt_config(int argc, char **argv, int *bad)
{
	const char *cfg = NULL;
	*bad = 0;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
			if (i + 1 >= argc) {
				fprintf(stderr, "trustmebro: %s needs a file argument\n", argv[i]);
				*bad = 1;
				return NULL;
			}
			cfg = argv[++i];
		} else if (argv[i][0] == '-' && argv[i][1]) {
			fprintf(stderr, "trustmebro: unknown option %s\n", argv[i]);
			*bad = 1;
			return NULL;
		} else {
			fprintf(stderr, "trustmebro: unexpected argument %s\n", argv[i]);
			*bad = 1;
			return NULL;
		}
	}
	return cfg;
}

static char *resolve_config(const char *explicit)
{
	if (explicit && *explicit)
		return xstrdup(explicit);
	const char *env = getenv("TRUSTMEBRO_CONFIG");
	if (env && *env)
		return xstrdup(env);
	return cfg_discover();
}

static int load_checked(const char *path, struct config *cfg)
{
	char err[2048];
	if (cfg_load(path, cfg, err, sizeof(err)) != 0) {
		fprintf(stderr, "trustmebro: invalid config (%s):\n  %s\n", path, err);
		return -1;
	}
	return 0;
}

static void mkdirp(const char *dir)
{
	char *dup = xstrdup(dir);
	for (char *p = dup + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(dup, 0755);
			*p = '/';
		}
	}
	mkdir(dup, 0755);
}

static int link_force(const char *target, const char *link)
{
	unlink(link);
	return symlink(target, link);
}

/* Drops our own stale shims; never touches symlinks we did not create. */
static int sync_shims(const struct config *cfg, int verbose)
{
	char *self = self_path();
	if (!self) {
		fprintf(stderr, "trustmebro: cannot locate own binary\n");
		return -1;
	}
	char *sd = shim_dir();
	mkdirp(sd);

	DIR *d = opendir(sd);
	if (d) {
		struct dirent *e;
		while ((e = readdir(d))) {
			if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
				continue;
			char link[PATH_MAX];
			snprintf(link, sizeof(link), "%s/%s", sd, e->d_name);
			char tgt[PATH_MAX];
			ssize_t n = readlink(link, tgt, sizeof(tgt) - 1);
			if (n < 0)
				continue;
			tgt[n] = '\0';
			char *base = strrchr(tgt, '/');
			base = base ? base + 1 : tgt;
			if (strcmp(base, "trustmebro") && strcmp(base, "tmb"))
				continue;
			int wanted = 0;
			for (int i = 0; i < cfg->nshims; i++)
				if (!strcmp(cfg->shims[i], e->d_name))
					wanted = 1;
			if (!wanted) {
				unlink(link);
				if (verbose)
					printf("removed stale shim %s\n", link);
			}
		}
		closedir(d);
	}

	for (int i = 0; i < cfg->nshims; i++) {
		char link[PATH_MAX];
		snprintf(link, sizeof(link), "%s/%s", sd, cfg->shims[i]);
		if (link_force(self, link) != 0) {
			fprintf(stderr, "trustmebro: link %s: %s\n", link, strerror(errno));
			return -1;
		}
		if (verbose)
			printf("shim %s -> %s\n", link, self);
	}
	return 0;
}

#define AGENT_STATE_HEADER "trustmebro-agent-shims-v1"
#define INSTALL_STATE_HEADER "trustmebro-install-v1"

struct agent_state {
	char *self;
	char *dir;
	char **names;
	int nnames;
};

static char *path_join(const char *dir, const char *name)
{
	size_t n = strlen(dir) + strlen(name) + 2;
	char *out = xmalloc(n);
	snprintf(out, n, "%s/%s", dir, name);
	return out;
}

static char *path_parent(const char *path)
{
	char *out = xstrdup(path);
	char *slash = strrchr(out, '/');
	if (!slash)
		return NULL;
	if (slash == out)
		slash[1] = '\0';
	else
		*slash = '\0';
	return out;
}

static char *agent_state_dir(void)
{
	const char *xdg = getenv("XDG_STATE_HOME");
	if (xdg && *xdg)
		return path_join(xdg, "trustmebro");
	return expand_home("~/.local/state/trustmebro");
}

static char *agent_state_path(void)
{
	char *dir = agent_state_dir();
	return path_join(dir, "agent-shims");
}

static char *install_state_path(void)
{
	char *dir = agent_state_dir();
	return path_join(dir, "installation");
}

static char *global_config_path(void)
{
	const char *xdg = getenv("XDG_CONFIG_HOME");
	if (xdg && *xdg) {
		char *dir = path_join(xdg, "trustmebro");
		return path_join(dir, "config.toml");
	}
	return expand_home("~/.config/trustmebro/config.toml");
}

static void mkdirp_private(const char *dir)
{
	char *dup = xstrdup(dir);
	for (char *p = dup + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(dup, 0700);
			*p = '/';
		}
	}
	mkdir(dup, 0700);
}

static char *state_line(FILE *f)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t n = getline(&line, &cap, f);
	if (n < 0)
		return NULL;
	while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
	return line;
}

/* Returns 1 when not installed, 0 when loaded, and -1 for invalid state. */
static int install_state_load(char **self)
{
	*self = NULL;
	char *path = install_state_path();
	FILE *f = fopen(path, "rb");
	if (!f) {
		if (errno == ENOENT)
			return 1;
		fprintf(stderr, "trustmebro: read %s: %s\n", path, strerror(errno));
		return -1;
	}
	char *header = state_line(f);
	char *binary = state_line(f);
	char *extra = state_line(f);
	fclose(f);
	const char *base = binary ? strrchr(binary, '/') : NULL;
	base = base ? base + 1 : NULL;
	if (!header || strcmp(header, INSTALL_STATE_HEADER) || !binary ||
	    binary[0] != '/' || !base || strcmp(base, "trustmebro") || extra) {
		fprintf(stderr, "trustmebro: invalid installation state in %s\n", path);
		return -1;
	}
	*self = binary;
	return 0;
}

static int install_state_write(const char *self)
{
	char *state_dir = agent_state_dir();
	char *path = install_state_path();
	mkdirp_private(state_dir);
	size_t n = strlen(path) + 40;
	char *tmp = xmalloc(n);
	snprintf(tmp, n, "%s.tmp.%ld", path, (long)getpid());
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		fprintf(stderr, "trustmebro: write %s: %s\n", tmp, strerror(errno));
		return -1;
	}
	FILE *f = fdopen(fd, "wb");
	if (!f) {
		fprintf(stderr, "trustmebro: write %s: %s\n", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		return -1;
	}
	fprintf(f, "%s\n%s\n", INSTALL_STATE_HEADER, self);
	if (fclose(f) != 0 || rename(tmp, path) != 0) {
		fprintf(stderr, "trustmebro: install %s: %s\n", path, strerror(errno));
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* Returns 1 when disabled, 0 when loaded, and -1 for invalid state. */
static int agent_state_load(struct agent_state *st)
{
	memset(st, 0, sizeof(*st));
	char *path = agent_state_path();
	FILE *f = fopen(path, "rb");
	if (!f) {
		if (errno == ENOENT)
			return 1;
		fprintf(stderr, "trustmebro: read %s: %s\n", path, strerror(errno));
		return -1;
	}

	char *header = state_line(f);
	st->self = state_line(f);
	st->dir = state_line(f);
	if (!header || strcmp(header, AGENT_STATE_HEADER) ||
	    !st->self || st->self[0] != '/' || !st->dir || st->dir[0] != '/') {
		fprintf(stderr, "trustmebro: invalid agent integration state in %s\n", path);
		fclose(f);
		return -1;
	}

	char *parent = path_parent(st->self);
	if (!parent || strcmp(parent, st->dir)) {
		fprintf(stderr, "trustmebro: invalid agent integration paths in %s\n", path);
		fclose(f);
		return -1;
	}

	int cap = 0;
	char *line;
	while ((line = state_line(f))) {
		if (!valid_command_name(line) || !strcmp(line, "trustmebro") || !strcmp(line, "tmb")) {
			fprintf(stderr, "trustmebro: invalid shim name in %s\n", path);
			fclose(f);
			return -1;
		}
		if (st->nnames >= cap) {
			cap = cap ? cap * 2 : 4;
			st->names = xrealloc(st->names, cap * sizeof(char *));
		}
		st->names[st->nnames++] = line;
	}
	fclose(f);
	if (st->nnames == 0) {
		fprintf(stderr, "trustmebro: agent integration state has no shims\n");
		return -1;
	}
	return 0;
}

static int agent_state_write(const char *self, const char *dir, const struct config *cfg)
{
	char *state_dir = agent_state_dir();
	char *path = agent_state_path();
	mkdirp_private(state_dir);

	size_t n = strlen(path) + 40;
	char *tmp = xmalloc(n);
	snprintf(tmp, n, "%s.tmp.%ld", path, (long)getpid());
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		fprintf(stderr, "trustmebro: write %s: %s\n", tmp, strerror(errno));
		return -1;
	}
	FILE *f = fdopen(fd, "wb");
	if (!f) {
		fprintf(stderr, "trustmebro: write %s: %s\n", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		return -1;
	}
	fprintf(f, "%s\n%s\n%s\n", AGENT_STATE_HEADER, self, dir);
	for (int i = 0; i < cfg->nshims; i++)
		fprintf(f, "%s\n", cfg->shims[i]);
	if (fclose(f) != 0) {
		fprintf(stderr, "trustmebro: write %s: %s\n", tmp, strerror(errno));
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path) != 0) {
		fprintf(stderr, "trustmebro: install %s: %s\n", path, strerror(errno));
		unlink(tmp);
		return -1;
	}
	return 0;
}

static int path_has_dir(const char *wanted)
{
	const char *path = getenv("PATH");
	if (!path)
		return 0;
	const char *p = path;
	for (;;) {
		const char *end = strchr(p, ':');
		size_t len = end ? (size_t)(end - p) : strlen(p);
		char *entry = len ? xstrndup(p, len) : xstrdup(".");
		char resolved[PATH_MAX];
		if (realpath(entry, resolved) && !strcmp(resolved, wanted))
			return 1;
		if (!end)
			break;
		p = end + 1;
	}
	return 0;
}

static char *user_install_dir(void)
{
	char *dir = expand_home("~/.local/bin");
	if (path_has_dir(dir) && access(dir, W_OK) == 0)
		return dir;
	dir = expand_home("~/bin");
	if (path_has_dir(dir) && access(dir, W_OK) == 0)
		return dir;
	return NULL;
}

static int files_equal(const char *a, const char *b)
{
	FILE *fa = fopen(a, "rb");
	FILE *fb = fopen(b, "rb");
	if (!fa || !fb) {
		if (fa) fclose(fa);
		if (fb) fclose(fb);
		return 0;
	}
	struct stat sa, sb;
	if (fstat(fileno(fa), &sa) != 0 || fstat(fileno(fb), &sb) != 0 ||
	    !S_ISREG(sa.st_mode) || !S_ISREG(sb.st_mode) || sa.st_size != sb.st_size) {
		fclose(fa);
		fclose(fb);
		return 0;
	}
	char ba[65536], bb[65536];
	int equal = 1;
	for (;;) {
		size_t na = fread(ba, 1, sizeof(ba), fa);
		size_t nb = fread(bb, 1, sizeof(bb), fb);
		if (na != nb || (na > 0 && memcmp(ba, bb, na)) || ferror(fa) || ferror(fb)) {
			equal = 0;
			break;
		}
		if (na == 0)
			break;
	}
	fclose(fa);
	fclose(fb);
	return equal;
}

static int copy_executable(const char *src, const char *dst, int replace,
			   struct stat *installed)
{
	int in = open(src, O_RDONLY);
	if (in < 0) {
		fprintf(stderr, "trustmebro: read %s: %s\n", src, strerror(errno));
		return -1;
	}
	struct stat srcstat;
	if (fstat(in, &srcstat) != 0) {
		fprintf(stderr, "trustmebro: inspect %s: %s\n", src, strerror(errno));
		close(in);
		return -1;
	}

	size_t n = strlen(dst) + 40;
	char *tmp = xmalloc(n);
	snprintf(tmp, n, "%s.tmp.%ld", dst, (long)getpid());
	mode_t mode = srcstat.st_mode & 0777;
	if (!(mode & 0111))
		mode |= 0700;
	int out = open(tmp, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (out < 0) {
		fprintf(stderr, "trustmebro: write %s: %s\n", tmp, strerror(errno));
		close(in);
		return -1;
	}

	char buf[65536];
	int failed = 0;
	for (;;) {
		ssize_t got = read(in, buf, sizeof(buf));
		if (got == 0)
			break;
		if (got < 0) {
			if (errno == EINTR)
				continue;
			failed = 1;
			break;
		}
		ssize_t off = 0;
		while (off < got) {
			ssize_t put = write(out, buf + off, (size_t)(got - off));
			if (put < 0 && errno == EINTR)
				continue;
			if (put <= 0) {
				failed = 1;
				break;
			}
			off += put;
		}
		if (failed)
			break;
	}
	if (close(in) != 0 || close(out) != 0)
		failed = 1;
	if (failed) {
		fprintf(stderr, "trustmebro: copy %s to %s: %s\n", src, dst, strerror(errno));
		unlink(tmp);
		return -1;
	}
	int moved = replace ? rename(tmp, dst) : link(tmp, dst);
	if (moved != 0) {
		fprintf(stderr, "trustmebro: install %s: %s\n", dst, strerror(errno));
		unlink(tmp);
		return -1;
	}
	if (!replace)
		unlink(tmp);
	if (lstat(dst, installed) != 0) {
		fprintf(stderr, "trustmebro: inspect %s: %s\n", dst, strerror(errno));
		if (!replace)
			unlink(dst);
		return -1;
	}
	return 0;
}

static int copy_config(const char *src, const char *dst)
{
	int in = open(src, O_RDONLY);
	if (in < 0) {
		fprintf(stderr, "trustmebro: read %s: %s\n", src, strerror(errno));
		return -1;
	}
	struct stat srcstat;
	if (fstat(in, &srcstat) != 0 || !S_ISREG(srcstat.st_mode)) {
		fprintf(stderr, "trustmebro: config is not a regular file: %s\n", src);
		close(in);
		return -1;
	}
	char *dir = path_parent(dst);
	mkdirp_private(dir);
	size_t n = strlen(dst) + 40;
	char *tmp = xmalloc(n);
	snprintf(tmp, n, "%s.tmp.%ld", dst, (long)getpid());
	int out = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (out < 0) {
		fprintf(stderr, "trustmebro: write %s: %s\n", tmp, strerror(errno));
		close(in);
		return -1;
	}
	char buf[65536];
	int failed = 0;
	for (;;) {
		ssize_t got = read(in, buf, sizeof(buf));
		if (got == 0)
			break;
		if (got < 0) {
			if (errno == EINTR)
				continue;
			failed = 1;
			break;
		}
		ssize_t off = 0;
		while (off < got) {
			ssize_t put = write(out, buf + off, (size_t)(got - off));
			if (put < 0 && errno == EINTR)
				continue;
			if (put <= 0) {
				failed = 1;
				break;
			}
			off += put;
		}
		if (failed)
			break;
	}
	if (close(in) != 0 || close(out) != 0)
		failed = 1;
	if (failed) {
		fprintf(stderr, "trustmebro: copy %s to %s: %s\n", src, dst, strerror(errno));
		unlink(tmp);
		return -1;
	}
	if (link(tmp, dst) != 0) {
		fprintf(stderr, "trustmebro: install %s: %s\n", dst, strerror(errno));
		unlink(tmp);
		return -1;
	}
	unlink(tmp);
	return 0;
}

static void remove_installed_copy(const char *path, const struct stat *installed)
{
	struct stat current;
	if (lstat(path, &current) == 0 && current.st_dev == installed->st_dev &&
	    current.st_ino == installed->st_ino)
		unlink(path);
}

static int link_points_to(const char *link, const char *target)
{
	char buf[PATH_MAX];
	ssize_t n = readlink(link, buf, sizeof(buf) - 1);
	if (n < 0)
		return 0;
	buf[n] = '\0';
	return !strcmp(buf, target);
}

static int agent_state_clear(void)
{
	char *path = agent_state_path();
	if (unlink(path) != 0 && errno != ENOENT) {
		fprintf(stderr, "trustmebro: remove %s: %s\n", path, strerror(errno));
		return -1;
	}
	char *dir = agent_state_dir();
	if (rmdir(dir) != 0 && errno != ENOTEMPTY && errno != ENOENT) {
		fprintf(stderr, "trustmebro: remove empty %s: %s\n", dir, strerror(errno));
		return -1;
	}
	return 0;
}

static int install_state_clear(void)
{
	char *path = install_state_path();
	if (unlink(path) != 0 && errno != ENOENT) {
		fprintf(stderr, "trustmebro: remove %s: %s\n", path, strerror(errno));
		return -1;
	}
	char *dir = agent_state_dir();
	if (rmdir(dir) != 0 && errno != ENOTEMPTY && errno != ENOENT) {
		fprintf(stderr, "trustmebro: remove empty %s: %s\n", dir, strerror(errno));
		return -1;
	}
	return 0;
}

static int agent_disable(int verbose)
{
	struct agent_state st;
	int loaded = agent_state_load(&st);
	if (loaded == 1) {
		if (verbose)
			printf("agent interception is disabled\n");
		return 0;
	}
	if (loaded < 0)
		return 1;

	int changed = 0;
	int failed = 0;
	for (int i = 0; i < st.nnames; i++) {
		char *link = path_join(st.dir, st.names[i]);
		struct stat sb;
		if (lstat(link, &sb) != 0) {
			if (errno != ENOENT) {
				fprintf(stderr, "trustmebro: inspect %s: %s\n", link, strerror(errno));
				failed = 1;
			}
			continue;
		}
		if (!S_ISLNK(sb.st_mode) || !link_points_to(link, st.self)) {
			fprintf(stderr, "trustmebro: not removing changed path %s\n", link);
			failed = 1;
			continue;
		}
		if (unlink(link) != 0) {
			fprintf(stderr, "trustmebro: remove %s: %s\n", link, strerror(errno));
			failed = 1;
		} else {
			changed++;
		}
	}
	if (failed) {
		fprintf(stderr, "trustmebro: integration state kept for another disable attempt\n");
		return 1;
	}

	if (agent_state_clear() != 0)
		return 1;
	if (verbose)
		printf("agent interception disabled. Removed %d shim%s\n",
		       changed, changed == 1 ? "" : "s");
	return 0;
}

static int agent_enable(const char *cfgarg)
{
	struct agent_state old;
	int loaded = agent_state_load(&old);
	if (loaded == 0) {
		printf("agent interception is already enabled. Disable it before changing shims\n");
		return 0;
	}
	if (loaded < 0)
		return 1;

	char *path = resolve_config(cfgarg);
	if (!path) {
		fprintf(stderr, "trustmebro: no config found, run 'trustmebro init' first\n");
		return 1;
	}
	struct config cfg;
	if (load_checked(path, &cfg) != 0)
		return 1;
	if (!cfg.activate) {
		fprintf(stderr, "trustmebro: enable needs `activate` with codex, claude, or pi\n");
		return 1;
	}

	char *self = NULL;
	int installed = install_state_load(&self);
	if (installed == 1) {
		fprintf(stderr, "trustmebro: not installed. Run 'trustmebro install' first\n");
		return 1;
	}
	if (installed < 0)
		return 1;
	struct stat binary;
	if (stat(self, &binary) != 0 || !S_ISREG(binary.st_mode) || access(self, X_OK) != 0) {
		fprintf(stderr, "trustmebro: installed binary is missing or not executable: %s\n", self);
		return 1;
	}
	char *dir = path_parent(self);

	for (int i = 0; i < cfg.nshims; i++) {
		char *link = path_join(dir, cfg.shims[i]);
		struct stat sb;
		if (lstat(link, &sb) == 0) {
			fprintf(stderr, "trustmebro: refusing to replace existing path %s\n", link);
			return 1;
		} else if (errno != ENOENT) {
			fprintf(stderr, "trustmebro: inspect %s: %s\n", link, strerror(errno));
			return 1;
		}
	}

	if (agent_state_write(self, dir, &cfg) != 0) {
		return 1;
	}
	int created = 0;
	for (int i = 0; i < cfg.nshims; i++) {
		char *link = path_join(dir, cfg.shims[i]);
		if (symlink(self, link) != 0) {
			fprintf(stderr, "trustmebro: create %s: %s\n", link, strerror(errno));
			int rollback_failed = 0;
			for (int j = 0; j < created; j++) {
				char *made = path_join(dir, cfg.shims[j]);
				if (!link_points_to(made, self) || unlink(made) != 0)
					rollback_failed = 1;
			}
			if (!rollback_failed)
				agent_state_clear();
			else
				fprintf(stderr, "trustmebro: integration state kept for cleanup with disable\n");
			return 1;
		}
		created++;
	}
	printf("agent interception enabled. Created %d shim%s\n",
	       created, created == 1 ? "" : "s");
	return 0;
}

static int cmd_enable(int argc, char **argv)
{
	int bad;
	const char *cfgarg = opt_config(argc, argv, &bad);
	if (bad)
		return 2;
	return agent_enable(cfgarg);
}

static int cmd_install(int argc, char **argv)
{
	int bad;
	const char *cfgarg = opt_config(argc, argv, &bad);
	if (bad)
		return 2;
	char *config = resolve_config(cfgarg);
	char *global = global_config_path();
	if (config) {
		struct config checked;
		if (load_checked(config, &checked) != 0)
			return 1;
		if (strcmp(config, global)) {
			struct stat config_stat;
			if (lstat(global, &config_stat) == 0) {
				if (!S_ISREG(config_stat.st_mode)) {
					fprintf(stderr, "trustmebro: global config is not a regular file: %s\n", global);
					return 1;
				}
				printf("kept existing global config at %s\n", global);
			} else if (errno != ENOENT) {
				fprintf(stderr, "trustmebro: inspect %s: %s\n", global, strerror(errno));
				return 1;
			} else if (copy_config(config, global) != 0) {
				return 1;
			} else {
				printf("installed config at %s\n", global);
			}
		}
	}
	char *source = self_path();
	if (!source) {
		fprintf(stderr, "trustmebro: cannot locate own binary\n");
		return 1;
	}
	char *recorded = NULL;
	int state = install_state_load(&recorded);
	if (state < 0)
		return 1;
	char *dir = state == 0 ? path_parent(recorded) : user_install_dir();
	if (!dir) {
		fprintf(stderr, "trustmebro: no writable user bin directory on PATH\n");
		return 1;
	}
	char *target = state == 0 ? recorded : path_join(dir, "trustmebro");
	int same_path = !strcmp(source, target);
	int exists = 0;
	int owned = state == 0;
	struct stat sb;
	if (lstat(target, &sb) == 0) {
		exists = 1;
		if (!S_ISREG(sb.st_mode)) {
			fprintf(stderr, "trustmebro: refusing to replace existing path %s\n", target);
			return 1;
		}
		if (!owned) {
			struct agent_state legacy;
			int old = agent_state_load(&legacy);
			owned = old == 0 && !strcmp(legacy.self, target);
			if (old < 0)
				return 1;
		}
		if (!owned && !files_equal(source, target)) {
			fprintf(stderr, "trustmebro: refusing to replace existing path %s\n", target);
			return 1;
		}
	} else if (errno != ENOENT) {
		fprintf(stderr, "trustmebro: inspect %s: %s\n", target, strerror(errno));
		return 1;
	}

	struct stat installed;
	memset(&installed, 0, sizeof(installed));
	int copied = !same_path && (!exists || !files_equal(source, target));
	if (copied && copy_executable(source, target, exists, &installed) != 0)
		return 1;
	if (install_state_write(target) != 0) {
		if (copied && !exists)
			remove_installed_copy(target, &installed);
		return 1;
	}
	printf("installed trustmebro at %s\n", target);
	if (!config) {
		printf("agent interception is disabled. Run 'trustmebro init', then 'trustmebro enable'\n");
		return 0;
	}
	return agent_enable(global);
}

static int cmd_disable(int argc, char **argv)
{
	(void)argv;
	if (argc != 0) {
		fprintf(stderr, "trustmebro: disable takes no arguments\n");
		return 2;
	}
	return agent_disable(1);
}

static int cmd_uninstall(int argc, char **argv)
{
	(void)argv;
	if (argc != 0) {
		fprintf(stderr, "trustmebro: uninstall takes no arguments\n");
		return 2;
	}
	if (agent_disable(1) != 0)
		return 1;
	char *installed = NULL;
	int state = install_state_load(&installed);
	if (state == 1) {
		printf("trustmebro is not installed\n");
		return 0;
	}
	if (state < 0)
		return 1;
	struct stat sb;
	if (lstat(installed, &sb) == 0) {
		if (!S_ISREG(sb.st_mode)) {
			fprintf(stderr, "trustmebro: not removing changed path %s\n", installed);
			return 1;
		}
		if (unlink(installed) != 0) {
			fprintf(stderr, "trustmebro: remove %s: %s\n", installed, strerror(errno));
			return 1;
		}
	} else if (errno != ENOENT) {
		fprintf(stderr, "trustmebro: inspect %s: %s\n", installed, strerror(errno));
		return 1;
	}
	if (install_state_clear() != 0)
		return 1;
	printf("uninstalled trustmebro from %s\n", installed);
	return 0;
}

static int cmd_status(int argc, char **argv)
{
	(void)argv;
	if (argc != 0) {
		fprintf(stderr, "trustmebro: status takes no arguments\n");
		return 2;
	}
	struct agent_state st;
	char *installed = NULL;
	int installation = install_state_load(&installed);
	if (installation < 0)
		return 1;
	if (installation == 0)
		printf("installation: installed (%s)\n", installed);
	else
		printf("installation: not installed\n");
	int loaded = agent_state_load(&st);
	if (loaded == 1) {
		printf("agent interception: disabled\n");
		return 0;
	}
	if (loaded < 0)
		return 1;
	int active = 0;
	for (int i = 0; i < st.nnames; i++) {
		char *link = path_join(st.dir, st.names[i]);
		if (link_points_to(link, st.self))
			active++;
	}
	printf("agent interception: enabled (%d/%d shims active)\n", active, st.nnames);
	return active == st.nnames ? 0 : 1;
}

static int cmd_run(int argc, char **argv)
{
	const char *cfgarg = NULL;
	int i = 0;
	for (; i < argc; i++) {
		if (!strcmp(argv[i], "--")) {
			i++;
			break;
		}
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage();
			return 0;
		}
		if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
			if (i + 1 >= argc) {
				fprintf(stderr, "trustmebro: %s needs a file argument\n", argv[i]);
				return 2;
			}
			cfgarg = argv[++i];
		} else if (argv[i][0] == '-' && argv[i][1]) {
			fprintf(stderr, "trustmebro: unknown option %s\n", argv[i]);
			return 2;
		} else {
			break;
		}
	}
	if (i >= argc) {
		fprintf(stderr, "trustmebro: run needs a command, e.g. trustmebro run -- codex\n");
		return 2;
	}

	char *path = resolve_config(cfgarg);
	if (!path) {
		fprintf(stderr, "trustmebro: no config found, run 'trustmebro init' first\n");
		return 1;
	}
	struct config cfg;
	if (load_checked(path, &cfg) != 0)
		return 1;
	if (sync_shims(&cfg, 0) != 0)
		return 1;

	char *sd = shim_dir();
	const char *old = getenv("PATH");
	if (!old)
		old = "";
	char *newpath = xmalloc(strlen(sd) + strlen(old) + 2);
	sprintf(newpath, "%s:%s", sd, old);
	setenv("PATH", newpath, 1);
	setenv("TRUSTMEBRO", "1", 1);
	char abspath[PATH_MAX];
	if (realpath(path, abspath))
		setenv("TRUSTMEBRO_CONFIG", abspath, 1);
	else
		setenv("TRUSTMEBRO_CONFIG", path, 1);

	execvp(argv[i], &argv[i]);
	fprintf(stderr, "trustmebro: cannot run %s: %s\n", argv[i], strerror(errno));
	return 127;
}

static int cmd_init(int argc, char **argv)
{
	int force = 0;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--force") || !strcmp(argv[i], "-f"))
			force = 1;
		else {
			fprintf(stderr, "trustmebro: unexpected argument %s\n", argv[i]);
			return 2;
		}
	}
	const char *target = "trustmebro.toml";
	if (!force && access(target, F_OK) == 0) {
		fprintf(stderr, "trustmebro: %s already exists (use --force to overwrite)\n", target);
		return 1;
	}
	FILE *f = fopen(target, "wb");
	if (!f) {
		fprintf(stderr, "trustmebro: write %s: %s\n", target, strerror(errno));
		return 1;
	}
	fwrite(STARTER, 1, sizeof(STARTER) - 1, f);
	if (fclose(f) != 0) {
		fprintf(stderr, "trustmebro: write %s: %s\n", target, strerror(errno));
		return 1;
	}
	printf("wrote %s\n", target);
	char *install_argv[] = { "-c", (char *)target };
	return cmd_install(2, install_argv);
}

static int cmd_check(int argc, char **argv)
{
	int bad;
	const char *cfgarg = opt_config(argc, argv, &bad);
	if (bad)
		return 2;
	char *path = resolve_config(cfgarg);
	if (!path) {
		fprintf(stderr, "trustmebro: no config found, run 'trustmebro init' first\n");
		return 1;
	}
	struct config cfg;
	if (load_checked(path, &cfg) != 0)
		return 1;
	printf("config:  %s\n", path);
	printf("default: %s\n", action_name(cfg.deflt));
	printf("activate:");
	if (cfg.activate & ACTIVATE_CODEX)
		printf(" codex");
	if (cfg.activate & ACTIVATE_CLAUDE)
		printf(" claude");
	if (cfg.activate & ACTIVATE_PI)
		printf(" pi");
	if (!cfg.activate)
		printf(" (run only)");
	printf("\n");
	printf("shims:  ");
	for (int i = 0; i < cfg.nshims; i++)
		printf(" %s", cfg.shims[i]);
	printf("\n");
	printf("log:     %s\n", cfg.log ? cfg.log : "(disabled)");
	printf("rules:   %d\n", cfg.nrules);
	printf("OK\n");
	return 0;
}

static int cmd_rules(int argc, char **argv)
{
	int bad;
	const char *cfgarg = opt_config(argc, argv, &bad);
	if (bad)
		return 2;
	char *path = resolve_config(cfgarg);
	if (!path) {
		fprintf(stderr, "trustmebro: no config found, run 'trustmebro init' first\n");
		return 1;
	}
	struct config cfg;
	if (load_checked(path, &cfg) != 0)
		return 1;
	if (cfg.nrules == 0)
		printf("no rules configured\n");
	for (int i = 0; i < cfg.nrules; i++) {
		struct rule *r = &cfg.rules[i];
		printf("%2d. %-24s command=%-8s action=%-11s",
		       i + 1, r->name ? r->name : "(unnamed)",
		       r->command && *r->command ? r->command : "*",
		       action_name(r->action));
		if (r->match && *r->match)
			printf(" match=%s", r->match);
		if (r->regex && *r->regex)
			printf(" regex=%s", r->regex);
		printf("\n");
	}
	return 0;
}

static int cmd_sync(int argc, char **argv)
{
	int bad;
	const char *cfgarg = opt_config(argc, argv, &bad);
	if (bad)
		return 2;
	char *path = resolve_config(cfgarg);
	if (!path) {
		fprintf(stderr, "trustmebro: no config found, run 'trustmebro init' first\n");
		return 1;
	}
	struct config cfg;
	if (load_checked(path, &cfg) != 0)
		return 1;
	if (sync_shims(&cfg, 1) != 0)
		return 1;
	return 0;
}

static int cmd_path(int argc, char **argv)
{
	(void)argv;
	if (argc != 0) {
		fprintf(stderr, "trustmebro: path takes no arguments\n");
		return 2;
	}
	printf("%s\n", shim_dir());
	return 0;
}

int cli_main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 0;
	}
	const char *cmd = argv[1];
	int rest = argc - 2;
	char **ra = argv + 2;

	if (!strcmp(cmd, "run"))
		return cmd_run(rest, ra);
	if (!strcmp(cmd, "init"))
		return cmd_init(rest, ra);
	if (!strcmp(cmd, "check"))
		return cmd_check(rest, ra);
	if (!strcmp(cmd, "rules"))
		return cmd_rules(rest, ra);
	if (!strcmp(cmd, "sync"))
		return cmd_sync(rest, ra);
	if (!strcmp(cmd, "install"))
		return cmd_install(rest, ra);
	if (!strcmp(cmd, "uninstall"))
		return cmd_uninstall(rest, ra);
	if (!strcmp(cmd, "enable"))
		return cmd_enable(rest, ra);
	if (!strcmp(cmd, "disable"))
		return cmd_disable(rest, ra);
	if (!strcmp(cmd, "status"))
		return cmd_status(rest, ra);
	if (!strcmp(cmd, "path"))
		return cmd_path(rest, ra);
	if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		usage();
		return 0;
	}
	if (!strcmp(cmd, "version") || !strcmp(cmd, "-v") || !strcmp(cmd, "--version")) {
		printf("trustmebro %s\n", TMB_VERSION);
		return 0;
	}
	fprintf(stderr, "trustmebro: unknown command %s\n\n", cmd);
	usage();
	return 2;
}
