
#include "app_common.h"
#include "util-config.h"

int config_init(const char *path)
{
	return 0;
}

int config_free()
{
	return 0;
}

const char* config_getstr(const char *title, const char *key, const char *def)
{
	return def;
}

int config_getint(const char *title, const char *key, int def)
{
	const char *ret = config_getstr(title, key, NULL);
	if (ret == NULL)
		return def;
	return atoi(ret);
}

int config_setint(const char *title, const char *key, const char *new_value)
{
	return -1;
}

int config_setstr(const char *title, const char *key, const char *new_value)
{
	return -1;
}

int config_remove_key(const char *title, const char *key)
{
	return -1;
}

int config_remove_group(const char *title, const char *key)
{
	return -1;
}