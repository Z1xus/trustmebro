/* TOML subset: top-level scalars, string arrays, [[rule]] tables. */
#define _GNU_SOURCE
#include "tmb.h"

#include <limits.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *action_name(enum action a)
{
	switch (a) {
	case ACT_PASSTHROUGH: return "passthrough";
	case ACT_SPOOF:       return "spoof";
	case ACT_REWRITE:     return "rewrite";
	case ACT_REJECT:      return "reject";
	}
	return "?";
}

struct errbuf {
	char *buf;
	size_t sz;
	size_t used;
	int count;
};

static void err_add(struct errbuf *e, const char *fmt, ...)
{
	e->count++;
	if (!e->buf || e->used + 4 >= e->sz)
		return;
	char *p = e->buf + e->used;
	size_t room = e->sz - e->used;
	if (e->used) {
		int k = snprintf(p, room, "\n  ");
		if (k < 0 || (size_t)k >= room)
			return;
		p += k;
		room -= k;
		e->used += k;
	}
	va_list ap;
	va_start(ap, fmt);
	int k = vsnprintf(p, room, fmt, ap);
	va_end(ap);
	if (k > 0)
		e->used += (size_t)k < room ? (size_t)k : room - 1;
}

struct parser {
	const char *s;
	size_t len;
	size_t pos;
	int line;
	struct errbuf *e;
	int fatal;
};

enum vtype { V_STR, V_INT, V_ARR };

struct value {
	enum vtype type;
	char *str;
	long i;
	char **arr;
	int narr;
};

static int pc(struct parser *p)
{
	return p->pos < p->len ? (unsigned char)p->s[p->pos] : -1;
}

static int pc2(struct parser *p)
{
	return p->pos + 1 < p->len ? (unsigned char)p->s[p->pos + 1] : -1;
}

static int adv(struct parser *p)
{
	int c = pc(p);
	if (c == '\n')
		p->line++;
	if (p->pos < p->len)
		p->pos++;
	return c;
}

static void skip_inline_ws(struct parser *p)
{
	while (pc(p) == ' ' || pc(p) == '\t' || pc(p) == '\r')
		adv(p);
}

static void skip_ws(struct parser *p)
{
	for (;;) {
		int c = pc(p);
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			adv(p);
		} else if (c == '#') {
			while (pc(p) != '\n' && pc(p) != -1)
				adv(p);
		} else {
			return;
		}
	}
}

static void pfail(struct parser *p, const char *fmt, ...)
{
	char msg[160];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	err_add(p->e, "line %d: %s", p->line, msg);
	p->fatal = 1;
}

static int starts(struct parser *p, const char *lit)
{
	size_t n = strlen(lit);
	return p->pos + n <= p->len && memcmp(p->s + p->pos, lit, n) == 0;
}

static char *read_delimited(struct parser *p, char q, int triple, int basic)
{
	size_t cap = 32, n = 0;
	char *out = xmalloc(cap);
	if (triple && pc(p) == '\n')
		adv(p);
	for (;;) {
		int c = pc(p);
		if (c == -1) {
			pfail(p, "unterminated string");
			out[n] = '\0';
			return out;
		}
		if (!triple && c == q) {
			adv(p);
			break;
		}
		if (triple && c == q && pc2(p) == q &&
		    p->pos + 2 < p->len && (unsigned char)p->s[p->pos + 2] == (unsigned char)q) {
			adv(p); adv(p); adv(p);
			break;
		}
		if (!triple && c == '\n') {
			pfail(p, "newline in single-line string");
			out[n] = '\0';
			return out;
		}
		if (basic && c == '\\') {
			adv(p);
			int e = adv(p);
			switch (e) {
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			case 'f': c = '\f'; break;
			case 'b': c = '\b'; break;
			case '0': c = '\0'; break;
			case '"': c = '"'; break;
			case '\\': c = '\\'; break;
			default: c = e; break;
			}
		} else {
			adv(p);
		}
		if (n + 1 >= cap) {
			cap *= 2;
			out = xrealloc(out, cap);
		}
		out[n++] = (char)c;
	}
	if (n + 1 >= cap)
		out = xrealloc(out, cap + 1);
	out[n] = '\0';
	return out;
}

static char *parse_string(struct parser *p)
{
	if (starts(p, "\"\"\"")) {
		adv(p); adv(p); adv(p);
		return read_delimited(p, '"', 1, 1);
	}
	if (starts(p, "'''")) {
		adv(p); adv(p); adv(p);
		return read_delimited(p, '\'', 1, 0);
	}
	if (pc(p) == '"') {
		adv(p);
		return read_delimited(p, '"', 0, 1);
	}
	if (pc(p) == '\'') {
		adv(p);
		return read_delimited(p, '\'', 0, 0);
	}
	pfail(p, "expected a string value");
	return xstrdup("");
}

static int parse_value(struct parser *p, struct value *v)
{
	skip_inline_ws(p);
	int c = pc(p);
	if (c == '"' || c == '\'') {
		v->type = V_STR;
		v->str = parse_string(p);
		return !p->fatal;
	}
	if (c == '[') {
		adv(p);
		v->type = V_ARR;
		v->arr = NULL;
		v->narr = 0;
		size_t cap = 0;
		for (;;) {
			skip_ws(p);
			if (pc(p) == ']') {
				adv(p);
				break;
			}
			if (pc(p) == -1) {
				pfail(p, "unterminated array");
				return 0;
			}
			if (pc(p) != '"' && pc(p) != '\'') {
				pfail(p, "arrays may only hold strings");
				return 0;
			}
			char *s = parse_string(p);
			if (p->fatal)
				return 0;
			if ((size_t)v->narr >= cap) {
				cap = cap ? cap * 2 : 4;
				v->arr = xrealloc(v->arr, cap * sizeof(char *));
			}
			v->arr[v->narr++] = s;
			skip_ws(p);
			if (pc(p) == ',')
				adv(p);
			else if (pc(p) != ']') {
				pfail(p, "expected ',' or ']' in array");
				return 0;
			}
		}
		return 1;
	}
	if (c == '-' || c == '+' || (c >= '0' && c <= '9')) {
		char num[32];
		size_t n = 0;
		while ((pc(p) == '-' || pc(p) == '+' || pc(p) == '_' ||
			(pc(p) >= '0' && pc(p) <= '9')) && n < sizeof(num) - 1) {
			int d = adv(p);
			if (d != '_')
				num[n++] = (char)d;
		}
		num[n] = '\0';
		v->type = V_INT;
		v->i = strtol(num, NULL, 10);
		return 1;
	}
	pfail(p, "unexpected value");
	return 0;
}

struct raw {
	char *deflt;
	char **activate;
	int nactivate;
	char **shims;
	int nshims;
	char *log;
	struct rule *rules;
	int nrules;
	int cap;
};

static struct rule *raw_new_rule(struct raw *r)
{
	if (r->nrules >= r->cap) {
		r->cap = r->cap ? r->cap * 2 : 8;
		r->rules = xrealloc(r->rules, r->cap * sizeof(struct rule));
	}
	struct rule *ru = &r->rules[r->nrules++];
	memset(ru, 0, sizeof(*ru));
	ru->exit_code = 0;
	return ru;
}

static void assign_top(struct parser *p, struct raw *r, const char *key, struct value *v)
{
	if (!strcmp(key, "default")) {
		if (v->type != V_STR) { pfail(p, "`default` must be a string"); return; }
		r->deflt = v->str;
	} else if (!strcmp(key, "activate")) {
		if (v->type == V_STR) {
			r->activate = xmalloc(sizeof(char *));
			r->activate[0] = v->str;
			r->nactivate = 1;
		} else if (v->type == V_ARR) {
			r->activate = v->arr;
			r->nactivate = v->narr;
		} else {
			pfail(p, "`activate` must be a string or array of strings");
		}
	} else if (!strcmp(key, "shims")) {
		if (v->type != V_ARR) { pfail(p, "`shims` must be an array of strings"); return; }
		r->shims = v->arr;
		r->nshims = v->narr;
	} else if (!strcmp(key, "log")) {
		if (v->type != V_STR) { pfail(p, "`log` must be a string"); return; }
		r->log = v->str;
	} else {
		pfail(p, "unknown top-level key `%s`", key);
	}
}

static void assign_rule(struct parser *p, struct rule *ru, const char *key, struct value *v)
{
	if (!strcmp(key, "action")) {
		if (v->type != V_STR) { pfail(p, "`action` must be a string"); return; }
		if (!strcmp(v->str, "spoof")) ru->action = ACT_SPOOF;
		else if (!strcmp(v->str, "rewrite")) ru->action = ACT_REWRITE;
		else if (!strcmp(v->str, "passthrough")) ru->action = ACT_PASSTHROUGH;
		else if (!strcmp(v->str, "reject")) ru->action = ACT_REJECT;
		else { pfail(p, "action `%s` must be spoof, rewrite, passthrough, or reject", v->str); return; }
		ru->action_set = 1;
		return;
	}
	if (!strcmp(key, "exit")) {
		if (v->type != V_INT) { pfail(p, "`exit` must be an integer"); return; }
		ru->exit_code = (int)v->i;
		ru->exit_set = 1;
		return;
	}

	char **strf = NULL;
	if (!strcmp(key, "name")) strf = &ru->name;
	else if (!strcmp(key, "command")) strf = &ru->command;
	else if (!strcmp(key, "match")) strf = &ru->match;
	else if (!strcmp(key, "regex")) strf = &ru->regex;
	else if (!strcmp(key, "stdout")) strf = &ru->out;
	else if (!strcmp(key, "stderr")) strf = &ru->err;
	else if (!strcmp(key, "find")) strf = &ru->find;
	else if (!strcmp(key, "replace")) strf = &ru->replace;

	if (strf) {
		if (v->type != V_STR) { pfail(p, "`%s` must be a string", key); return; }
		*strf = v->str;
		return;
	}
	pfail(p, "unknown rule key `%s`", key);
}

static int regex_ok(struct errbuf *e, const char *label, const char *field, const char *pat)
{
	regex_t re;
	int rc = regcomp(&re, pat, REG_EXTENDED);
	if (rc != 0) {
		char msg[128];
		regerror(rc, &re, msg, sizeof(msg));
		err_add(e, "%s: %s `%s`: %s", label, field, pat, msg);
		return 0;
	}
	regfree(&re);
	return 1;
}

static int build_config(struct raw *r, struct config *cfg, struct errbuf *e)
{
	memset(cfg, 0, sizeof(*cfg));

	cfg->deflt = ACT_PASSTHROUGH;
	if (r->deflt) {
		if (!strcmp(r->deflt, "passthrough")) cfg->deflt = ACT_PASSTHROUGH;
		else if (!strcmp(r->deflt, "reject")) cfg->deflt = ACT_REJECT;
		else err_add(e, "`default` must be passthrough or reject, got `%s`", r->deflt);
	}
	for (int i = 0; i < r->nactivate; i++) {
		const char *name = r->activate[i];
		if (!strcmp(name, "codex"))
			cfg->activate |= ACTIVATE_CODEX;
		else if (!strcmp(name, "claude"))
			cfg->activate |= ACTIVATE_CLAUDE;
		else
			err_add(e, "`activate` entry `%s` must be codex or claude", name);
	}

	cfg->rules = r->rules;
	cfg->nrules = r->nrules;
	cfg->log = (r->log && *r->log) ? expand_home(r->log) : NULL;

	/* shims come from the explicit list plus every concrete rule command */
	int cap = r->nshims + r->nrules + 1;
	cfg->shims = xmalloc(cap * sizeof(char *));
	cfg->nshims = 0;
	for (int i = 0; i < r->nshims; i++) {
		const char *s = r->shims[i];
		if (!valid_command_name(s)) {
			err_add(e, "shims: `%s` is not a plain command name", s);
			continue;
		}
		if (!strcmp(s, "trustmebro") || !strcmp(s, "tmb")) {
			err_add(e, "shims: `%s` collides with the CLI", s);
			continue;
		}
		int dup = 0;
		for (int j = 0; j < cfg->nshims; j++)
			if (!strcmp(cfg->shims[j], s)) dup = 1;
		if (!dup)
			cfg->shims[cfg->nshims++] = xstrdup(s);
	}

	for (int i = 0; i < cfg->nrules; i++) {
		struct rule *ru = &cfg->rules[i];
		char label[96];
		if (ru->name && *ru->name)
			snprintf(label, sizeof(label), "rule \"%s\"", ru->name);
		else
			snprintf(label, sizeof(label), "rule #%d", i + 1);

		if (!ru->name || !*ru->name)
			err_add(e, "%s: `name` is required", label);
		for (int j = 0; j < i; j++)
			if (ru->name && cfg->rules[j].name && !strcmp(ru->name, cfg->rules[j].name)) {
				err_add(e, "%s: duplicate name", label);
				break;
			}

		if (ru->command && strcmp(ru->command, "*") && !valid_command_name(ru->command))
			err_add(e, "%s: command `%s` must be a plain name or *", label, ru->command);

		if (ru->command && *ru->command && strcmp(ru->command, "*") &&
		    valid_command_name(ru->command) &&
		    strcmp(ru->command, "trustmebro") && strcmp(ru->command, "tmb")) {
			int dup = 0;
			for (int j = 0; j < cfg->nshims; j++)
				if (!strcmp(cfg->shims[j], ru->command)) dup = 1;
			if (!dup)
				cfg->shims[cfg->nshims++] = xstrdup(ru->command);
		}

		if (ru->regex && *ru->regex)
			regex_ok(e, label, "regex", ru->regex);
		if (ru->find && *ru->find)
			regex_ok(e, label, "find", ru->find);
		if (ru->exit_set && (ru->exit_code < 0 || ru->exit_code > 255))
			err_add(e, "%s: exit must be 0..255", label);

		int has_spoof = (ru->out && *ru->out) || (ru->err && *ru->err) || ru->exit_set;
		int has_rewrite = ru->find && *ru->find;
		if (has_spoof && has_rewrite)
			err_add(e, "%s: cannot combine stdout/stderr/exit with find/replace", label);

		if (!ru->action_set) {
			if (has_rewrite) ru->action = ACT_REWRITE;
			else if (has_spoof) ru->action = ACT_SPOOF;
			else ru->action = ACT_PASSTHROUGH;
		}
		if (ru->action == ACT_REWRITE && !has_rewrite)
			err_add(e, "%s: rewrite needs a `find` pattern", label);
		if (ru->replace && !has_rewrite && ru->action != ACT_REWRITE)
			err_add(e, "%s: `replace` needs a `find`", label);
	}

	if (cfg->nshims == 0)
		err_add(e, "no shims: set `shims` or give a rule a concrete `command`");

	return e->count == 0 ? 0 : -1;
}

int cfg_load(const char *path, struct config *cfg, char *err, size_t errsz)
{
	struct errbuf e = { .buf = err, .sz = errsz, .used = 0, .count = 0 };
	if (err && errsz)
		err[0] = '\0';

	FILE *f = fopen(path, "rb");
	if (!f) {
		err_add(&e, "cannot open %s", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	if (sz < 0)
		sz = 0;
	fseek(f, 0, SEEK_SET);
	char *buf = xmalloc((size_t)sz + 1);
	size_t got = fread(buf, 1, (size_t)sz, f);
	buf[got] = '\0';
	fclose(f);

	struct parser p = { .s = buf, .len = got, .pos = 0, .line = 1, .e = &e, .fatal = 0 };
	struct raw raw;
	memset(&raw, 0, sizeof(raw));
	struct rule *cur = NULL;

	while (!p.fatal) {
		skip_ws(&p);
		if (pc(&p) == -1)
			break;
		if (starts(&p, "[[")) {
			p.pos += 2;
			skip_inline_ws(&p);
			if (!starts(&p, "rule")) {
				pfail(&p, "only [[rule]] table arrays are supported");
				break;
			}
			p.pos += 4;
			skip_inline_ws(&p);
			if (!starts(&p, "]]")) {
				pfail(&p, "expected ]] after [[rule");
				break;
			}
			p.pos += 2;
			cur = raw_new_rule(&raw);
			continue;
		}
		if (pc(&p) == '[') {
			pfail(&p, "tables are not supported, use [[rule]] and top-level keys");
			break;
		}
		size_t start = p.pos;
		while (pc(&p) != -1) {
			int c = pc(&p);
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			    (c >= '0' && c <= '9') || c == '_' || c == '-')
				adv(&p);
			else
				break;
		}
		if (p.pos == start) {
			pfail(&p, "expected a key");
			break;
		}
		char *key = xstrndup(p.s + start, p.pos - start);
		skip_inline_ws(&p);
		if (pc(&p) != '=') {
			pfail(&p, "expected '=' after key `%s`", key);
			break;
		}
		adv(&p);
		struct value v;
		memset(&v, 0, sizeof(v));
		if (!parse_value(&p, &v))
			break;
		if (cur)
			assign_rule(&p, cur, key, &v);
		else
			assign_top(&p, &raw, key, &v);
		skip_inline_ws(&p);
		if (pc(&p) == '#') {
			while (pc(&p) != '\n' && pc(&p) != -1)
				adv(&p);
		}
		if (pc(&p) != '\n' && pc(&p) != -1) {
			pfail(&p, "unexpected text after value");
			break;
		}
	}

	if (p.fatal)
		return -1;

	int rc = build_config(&raw, cfg, &e);
	cfg->path = xstrdup(path);
	return rc;
}

static int exists(const char *p)
{
	return access(p, F_OK) == 0;
}

char *cfg_discover(void)
{
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd))) {
		char dir[PATH_MAX];
		snprintf(dir, sizeof(dir), "%s", cwd);
		for (;;) {
			char cand[PATH_MAX];
			int k = snprintf(cand, sizeof(cand), "%s/trustmebro.toml", dir);
			if (k > 0 && (size_t)k < sizeof(cand) && exists(cand))
				return xstrdup(cand);
			char *slash = strrchr(dir, '/');
			if (!slash || slash == dir)
				break;
			*slash = '\0';
		}
		if (exists("/trustmebro.toml"))
			return xstrdup("/trustmebro.toml");
	}

	const char *xdg = getenv("XDG_CONFIG_HOME");
	char *global;
	if (xdg && *xdg) {
		size_t n = strlen(xdg) + sizeof("/trustmebro/config.toml");
		global = xmalloc(n);
		snprintf(global, n, "%s/trustmebro/config.toml", xdg);
	} else {
		global = expand_home("~/.config/trustmebro/config.toml");
	}
	if (global && exists(global))
		return global;
	return NULL;
}
