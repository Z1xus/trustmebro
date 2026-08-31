#ifndef TMB_H
#define TMB_H

#include <stddef.h>

#define TMB_VERSION "0.3.0"

/* fail closed: a broken config must never fall back to the real command */
#define TMB_EXIT_CONFIG 78

enum action {
	ACT_PASSTHROUGH = 0,
	ACT_SPOOF,
	ACT_REWRITE,
	ACT_REJECT,
};

enum activation {
	ACTIVATE_CODEX  = 1u << 0,
	ACTIVATE_CLAUDE = 1u << 1,
	ACTIVATE_PI     = 1u << 2,
};

struct rule {
	char *name;
	char *command;
	char *match;
	char *regex;
	enum action action;
	int   action_set;
	char *out;
	char *err;
	int   exit_code;
	int   exit_set;
	char *find;
	char *replace;
};

struct config {
	enum action deflt;
	unsigned activate;
	char **shims;
	int    nshims;
	char  *log;
	struct rule *rules;
	int    nrules;
	char  *path;
};

int   cfg_load(const char *path, struct config *cfg, char *err, size_t errsz);
char *cfg_discover(void);
const char *action_name(enum action a);

void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
char *expand_home(const char *p);
char *join_args(int argc, char **argv, int from);
char *self_path(void);
int   valid_command_name(const char *s);
char *shim_dir(void);

int shim_main(const char *name, int argc, char **argv);
int cli_main(int argc, char **argv);

#endif
