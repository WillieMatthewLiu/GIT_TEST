/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : rsync.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.6.27
Description    : rsync config
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#include <glib.h>
#include "app_common.h"
#include "vector.h"
#include "thread.h"
#include "json-c.h"
#include "cmd_common.h"
#include "parser_common.h"
#include "rsync.h"

/************************************************************
*Function    : rsync_write_module
*Action      : get configuration file
*Input       : configfile   path of configuration file
			   module       para
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.6.27
*Instruction : null
************************************************************/
int rsync_write_module(const char *configfile, struct rsync_module_parameters *module)
{
	GKeyFileFlags flags;
	GError *error = NULL;
	GKeyFile *keyfile = NULL;

	keyfile = g_key_file_new();
	if (NULL == keyfile)
	{
		SCLogError("[%s:%d]g_key_file_new failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}

	flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
	if (!g_key_file_load_from_file(keyfile, configfile, flags, &error))
	{
		g_clear_error(&error);
	}

	if (g_key_file_has_group(keyfile, module->name))
	{
		if (!g_key_file_remove_group(keyfile, module->name, &error))
		{
			SCLogError("[%s:%d]g_key_file_remove_group failed, error reason:%s", __func__, __LINE__, error->message);
			g_clear_error(&error);
			g_key_file_free(keyfile);
			return PARSER_ERROR;
		}
	}

	SET_KEY_STRING(keyfile, module, auth_users, auth users);
	SET_KEY_STRING(keyfile, module, charset, charset);
	SET_KEY_STRING(keyfile, module, comment, comment);
	SET_KEY_STRING(keyfile, module, dont_compress, dont compress);
	SET_KEY_STRING(keyfile, module, exclude, exclude);
	SET_KEY_STRING(keyfile, module, exclude_from, exclude from);
	SET_KEY_STRING(keyfile, module, filter, filter);
	SET_KEY_STRING(keyfile, module, gid, gid);
	SET_KEY_STRING(keyfile, module, hosts_allow, hosts allow);
	SET_KEY_STRING(keyfile, module, hosts_deny, hosts deny);
	SET_KEY_STRING(keyfile, module, include, include);
	SET_KEY_STRING(keyfile, module, include_from, include from);
	SET_KEY_STRING(keyfile, module, incoming_chmod, incoming chmod);
	SET_KEY_STRING(keyfile, module, lock_file, lock file);
	SET_KEY_STRING(keyfile, module, log_file, log file);
	SET_KEY_STRING(keyfile, module, log_format, log format);
	SET_KEY_STRING(keyfile, module, outgoing_chmod, outgoing chmod);
	SET_KEY_STRING(keyfile, module, path, path);
	SET_KEY_STRING(keyfile, module, postxfer_exec, postxfer exec);
	SET_KEY_STRING(keyfile, module, prexfer_exec, prexfer exec);
	SET_KEY_STRING(keyfile, module, refuse_options, refuse options);
	SET_KEY_STRING(keyfile, module, secrets_file, secrets file);
	SET_KEY_STRING(keyfile, module, temp_dir, temp dir);
	SET_KEY_STRING(keyfile, module, uid, uid);
	SET_KEY_INTEGER(keyfile, module, max_connections, max connections);
	SET_KEY_INTEGER(keyfile, module, max_verbosity, max verbosity);
	SET_KEY_INTEGER(keyfile, module, syslog_facility, syslog facility);
	SET_KEY_INTEGER(keyfile, module, timeout, timeout);
	SET_KEY_BOOLEAN(keyfile, module, fake_super, fake super);
	SET_KEY_BOOLEAN(keyfile, module, forward_lookup, forward lookup);
	SET_KEY_BOOLEAN(keyfile, module, ignore_errors, ignore errors);
	SET_KEY_BOOLEAN(keyfile, module, ignore_nonreadable, ignore nonreadable);
	SET_KEY_BOOLEAN(keyfile, module, list, list);
	SET_KEY_BOOLEAN(keyfile, module, munge_symlinks, munge symlinks);
	SET_KEY_BOOLEAN(keyfile, module, numeric_ids, numeric ids);
	SET_KEY_BOOLEAN(keyfile, module, read_only, read only);
	SET_KEY_BOOLEAN(keyfile, module, reverse_lookup, reverse lookup);
	SET_KEY_BOOLEAN(keyfile, module, strict_modes, strict modes);
	SET_KEY_BOOLEAN(keyfile, module, transfer_logging, transfer logging);
	SET_KEY_BOOLEAN(keyfile, module, use_chroot, use chroot);
	SET_KEY_BOOLEAN(keyfile, module, write_only, write only);

	if (!g_key_file_save_to_file(keyfile, configfile, &error))
	{
		SCLogError("[%s:%d]g_key_file_save_to_file failed, error reason:%s", __func__, __LINE__, error->message);
		g_clear_error(&error);
		g_key_file_free(keyfile);
		return PARSER_ERROR;
	}

	g_key_file_free(keyfile);
	return PARSER_OK;
}

/************************************************************
*Function    : rsync_remove_module
*Action      : remove configuration
*Input       : configfile   path of configuration file
			   module_name  module name
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.6.27
*Instruction : null
************************************************************/
int rsync_remove_module(const char *configfile, const char *module_name)
{
	GKeyFileFlags flags;
	GError *error = NULL;
	GKeyFile *keyfile = NULL;

	keyfile = g_key_file_new();
	if (NULL == keyfile)
	{
		SCLogError("[%s:%d]g_key_file_new failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}

	flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
	if (!g_key_file_load_from_file(keyfile, configfile, flags, &error))
	{
		SCLogError("[%s:%d]g_key_file_load_from_file failed, error reason:%s", __func__, __LINE__, error->message);
		g_clear_error(&error);
		g_key_file_free(keyfile);
		return PARSER_ERROR;
	}

	if (g_key_file_has_group(keyfile, module_name))
	{
		if (!g_key_file_remove_group(keyfile, module_name, &error))
		{
			SCLogError("[%s:%d]g_key_file_remove_group failed, error reason:%s", __func__, __LINE__, error->message);
			g_clear_error(&error);
			g_key_file_free(keyfile);
			return PARSER_ERROR;
		}
	}
	else
	{
		g_key_file_free(keyfile);
		return PARSER_OK;
	}

	if (!g_key_file_save_to_file(keyfile, configfile, &error))
	{
		SCLogError("[%s:%d]g_key_file_save_to_file failed, error reason:%s", __func__, __LINE__, error->message);
		g_clear_error(&error);
		g_key_file_free(keyfile);
		return PARSER_ERROR;
	}

	g_key_file_free(keyfile);
	return PARSER_OK;
}

