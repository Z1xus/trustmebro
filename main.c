#define _GNU_SOURCE
#include "tmb.h"

#include <string.h>

static const char *base_name(const char *p)
{
	const char *slash = strrchr(p, '/');
	return slash ? slash + 1 : p;
}

int main(int argc, char **argv)
{
	const char *name = base_name(argc > 0 && argv[0] ? argv[0] : "trustmebro");
	if (!strcmp(name, "trustmebro") || !strcmp(name, "tmb"))
		return cli_main(argc, argv);
	return shim_main(name, argc, argv);
}
