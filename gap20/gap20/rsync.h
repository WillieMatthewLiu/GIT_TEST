#ifndef _RSYNC_H_
#define _RSYNC_H_

#ifndef BOOL
#define BOOL unsigned char
#endif

#define RSYNC_CONFIG_PATH      "/etc/rsyncd.conf"

#define SET_KEY_STRING(keyfile, module, member, key) (module->member) ? \
    g_key_file_set_string(keyfile, module->name, #key, module->member) : \
    g_key_file_remove_key(keyfile, module->name, #key, NULL)

#define SET_KEY_INTEGER(keyfile, module, member, key) (module->member) ? \
    g_key_file_set_integer(keyfile, module->name, #key, module->member) : \
    g_key_file_remove_key(keyfile, module->name, #key, NULL)

#define SET_KEY_BOOLEAN(keyfile, module, member, key) \
    g_key_file_set_string(keyfile, module->name, #key, (module->member) ? "yes" : "no")

struct rsync_module_parameters
{
	char *auth_users;
	char *charset;
	char *comment;
	char *dont_compress;
	char *exclude;
	char *exclude_from;
	char *filter;
	char *gid;
	char *hosts_allow;
	char *hosts_deny;
	char *include;
	char *include_from;
	char *incoming_chmod;
	char *lock_file;
	char *log_file;
	char *log_format;
	char *name;
	char *outgoing_chmod;
	char *path;
	char *postxfer_exec;
	char *prexfer_exec;
	char *refuse_options;
	char *secrets_file;
	char *temp_dir;
	char *uid;
	int max_connections;
	int max_verbosity;
	int syslog_facility;
	int timeout;
	BOOL fake_super;
	BOOL forward_lookup;
	BOOL ignore_errors;
	BOOL ignore_nonreadable;
	BOOL list;
	BOOL munge_symlinks;
	BOOL numeric_ids;
	BOOL read_only;
	BOOL reverse_lookup;
	BOOL strict_modes;
	BOOL transfer_logging;
	BOOL use_chroot;
	BOOL write_only;
};

/************************************************************
*Action      : get configuration file
*Input       : configfile   path of configuration file
*              module       configuration parameter
*Return      : 0            OK
*              -1           ERROR
*Instruction : 1. The user guarantees the validity of the parameter
*              2. string  : NULL stands for the default configuration
*                 integer : 0 stands for the default configuration
************************************************************/
int rsync_write_module(const char *configfile, struct rsync_module_parameters *module);

/************************************************************
*Action      : remove configuration
*Input       : configfile   path of configuration file
			   module_name  module name
*Return      : 0            OK
*              -1           ERROR
************************************************************/
int rsync_remove_module(const char *configfile, const char *module_name);

#endif

