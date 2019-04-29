#pragma once

int config_init(const char *path);
int config_free();

const char* config_getstr(const char *title, const char *key, const char *def);
int config_getint(const char *title, const char *key, int def);
int config_setint(const char *title, const char *key, const char *new_value);
int config_setstr(const char *title, const char *key, const char *new_value);