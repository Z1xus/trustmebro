/* Allocations live for the process; nothing frees, exit() reclaims. */
#define _GNU_SOURCE
#include "tmb.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <stdint.h>
#endif

static void oom(void)
{
	fputs("trustmebro: out of memory\n", stderr);
	exit(1);
}

void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		oom();
	return p;
}

void *xrealloc(void *p, size_t n)
{
	void *q = realloc(p, n ? n : 1);
	if (!q)
		oom();
	return q;
}

char *xstrdup(const char *s)
{
	char *p = strdup(s ? s : "");
	if (!p)
		oom();
	return p;
}

char *xstrndup(const char *s, size_t n)
{
	char *p = xmalloc(n + 1);
	memcpy(p, s, n);
	p[n] = '\0';
	return p;
}

char *expand_home(const char *p)
{
	if (!p)
		return NULL;
	if (p[0] == '~' && (p[1] == '\0' || p[1] == '/')) {
		const char *home = getenv("HOME");
		if (home && *home) {
			size_t n = strlen(home) + strlen(p);
			char *out = xmalloc(n + 1);
			snprintf(out, n + 1, "%s%s", home, p + 1);
			return out;
		}
	}
	return xstrdup(p);
}

char *join_args(int argc, char **argv, int from)
{
	size_t n = 1;
	for (int i = from; i < argc; i++)
		n += strlen(argv[i]) + 1;
	char *out = xmalloc(n);
	out[0] = '\0';
	for (int i = from; i < argc; i++) {
		if (i > from)
			strcat(out, " ");
		strcat(out, argv[i]);
	}
	return out;
}

char *self_path(void)
{
	char buf[PATH_MAX];
#if defined(__APPLE__)
	uint32_t size = sizeof(buf);
	if (_NSGetExecutablePath(buf, &size) == 0) {
		char resolved[PATH_MAX];
		if (realpath(buf, resolved))
			return xstrdup(resolved);
		return xstrdup(buf);
	}
#else
	ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		return xstrdup(buf);
	}
#endif
	return NULL;
}

int valid_command_name(const char *s)
{
	if (!s || !*s || !strcmp(s, ".") || !strcmp(s, ".."))
		return 0;
	if (strchr(s, '/') || strchr(s, '\\'))
		return 0;
	for (const char *c = s; *c; c++) {
		if (!isalnum((unsigned char)*c) && !strchr("._+-", *c))
			return 0;
	}
	return 1;
}

char *shim_dir(void)
{
	const char *xdg = getenv("XDG_DATA_HOME");
	if (xdg && *xdg) {
		size_t n = strlen(xdg) + sizeof("/trustmebro/shims");
		char *out = xmalloc(n);
		snprintf(out, n, "%s/trustmebro/shims", xdg);
		return out;
	}
	return expand_home("~/.local/share/trustmebro/shims");
}
