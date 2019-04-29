/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : gap_cmd_sync.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.3.29
Description    : SYNC VTY
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#include <pthread.h>
#include "vty.h"
#include "vtysh/vtysh.h"
#include "json-c.h"
#include "command.h"
#include "lib/memory.h"
#include "gap_cmd.h"
#include "gap_ctl.h"
#include "gap_ctl_ha.h"
#include "gap_ctl_conf.h"
#include "gap_ctl_adapter.h"
#include "parser_common.h"
#include "file_sync.h"
#include "gap_cmd_file_sync.h"

extern pthread_rwlock_t g_fileSyncLock;
extern struct list_head g_fileSyncConfig;

/************************************************************
*Function    : gap_ctl_show_sync_by_name
*Action      : display one task config info
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
DEFUN(gap_ctl_show_sync_by_name,
	gap_ctl_show_sync_by_name_cmd,
	"show file sync NAME",
	SHOW_STR
	"windows document\n"
	"sync\n"
	"name\n")
{
	SHARE_SYNC_PARA *pos = NULL;
	SHARE_SYNC_PARA *next = NULL;

	pthread_rwlock_rdlock(&g_fileSyncLock);
	list_for_each_entry_safe(pos, next, &g_fileSyncConfig, node)
	{
		if (strncmp(argv[0], pos->taskName, SHARE_SYNC_COMM_LEN) == 0)
		{
			vty_out(vty, "%s%s", JSON_FORMAT_STR(pos->json), VTY_NEWLINE);
			break;
		}
	}
	pthread_rwlock_unlock(&g_fileSyncLock);
	return CMD_SUCCESS;
}

/************************************************************
*Function    : gap_ctl_show_sync
*Action      : display all task config info
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
DEFUN(gap_ctl_show_sync,
	gap_ctl_show_sync_cmd,
	"show file sync",
	SHOW_STR
	"windows document\n"
	"sync\n")
{
	SHARE_SYNC_PARA *pos = NULL;

	pthread_rwlock_rdlock(&g_fileSyncLock);
	list_for_each_entry(pos, &g_fileSyncConfig, node)
	{
		vty_out(vty, "%s%s", JSON_FORMAT_STR(pos->json), VTY_NEWLINE);
	}
	pthread_rwlock_unlock(&g_fileSyncLock);
	return CMD_SUCCESS;
}

/************************************************************
*Function    : gap_ctl_sync_set_status_json
*Action      : set one config disable or enable
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
DEFUN(gap_ctl_sync_set_status_json,
	gap_ctl_sync_set_status_json_cmd,
	"file sync (enable|disable) NAME",
	"sync command\n"
	"set status sync rule.\n"
	"Json format string\n")
{
	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	if (argv[0][0] == 'e')
	{
		setOneConfigEnable(argv[1]);
	}
	else
	{
		setOneConfigDisable(argv[1]);
	}

	SCLogInfo("[%s:%d]set sync %s success, task(%s)", __func__, __LINE__, argv[0], argv[1]);

	return CMD_SUCCESS;
}

/************************************************************
*Function    : gap_ctl_sync_del_json
*Action      : delete on config
*Input       : null
*Output      : null
*Return      : CMD_SUCCESS
			   CMD_ERR_NOTHING_TODO
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
DEFUN(gap_ctl_sync_del_json,
	gap_ctl_sync_del_json_cmd,
	"no file sync NAME",
	"del sync rule.\n"
	"sync\n"
	"name\n")
{
	int ret;

	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	ret = delOneConfig(argv[0]);
	if (PARSER_OK != ret)
	{
		SCLogError("[%s:%d]delete file sync config failed, task(%s)!", __func__, __LINE__, argv[0]);
		if (PARSER_BUSY == ret)
		{
			vty_out(vty, "direcotry is busy, task(%s)!%s", argv[0], VTY_NEWLINE);
		}
		else
		{
			vty_out(vty, "delete file sync config failed, task(%s)!%s", argv[0], VTY_NEWLINE);
		}
		return CMD_SUCCESS;
	}

	SCLogInfo("[%s:%d]delete file sync config success, task(%s)", __func__, __LINE__, argv[0]);

	return CMD_SUCCESS;
}

#if GAP_DESC("Add sync config")
/************************************************************
*Function    : js_getIntByKey
*Action      : get json string int value of key
*Input       : jobj     json object
			   key      key
*Output      : null
*Return      : value
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static int js_getIntByKey(struct json_object *jobj, const char *key)
{
	int ret;
	struct json_object *pval = NULL;

	ret = json_object_object_get_ex(jobj, key, &pval);
	if ((!ret) || (NULL == pval))
	{
		SCLogError("[%s:%d]get json object of key(%s) failed", __func__, __LINE__, key);
		return -1;
	}

	return json_object_get_int(pval);
}

/************************************************************
*Function    : js_getStringByKey
*Action      : get json string string value of key
*Input       : jobj     json object
			   key      key
*Output      : null
*Return      : value
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static const char *js_getStringByKey(struct json_object *jobj, const char *key)
{
	int ret;
	struct json_object *pval = NULL;

	ret = json_object_object_get_ex(jobj, key, &pval);
	if ((!ret) || (NULL == pval))
	{
		SCLogError("[%s:%d]get json object of key(%s) failed", __func__, __LINE__, key);
		return NULL;
	}

	return json_object_get_string(pval);
}

/************************************************************
*Function    : getInnerConfig
*Action      : get inner config information
*Input       : jobj             json object
*Output      : syncConfigObj    config information
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static int getInnerConfig(struct json_object *jobj, SHARE_SYNC_PARA *syncConfigObj)
{
	int ret;
	const char *pstring = NULL;
	struct json_object *innerObj = NULL;

	/* get inner value */
	ret = json_object_object_get_ex(jobj, SYNC_CONFIG_INNER_NAME, &innerObj);
	if ((!ret) || (NULL == innerObj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_INNER_NAME);
		return PARSER_ERROR;
	}

	/* get dir */
	pstring = js_getStringByKey(innerObj, SYNC_CONFIG_DIR);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_DIR);
		return PARSER_ERROR;
	}
	syncConfigObj->inFolder.folderName = SCStrdup(pstring);

	/* get ip */
	pstring = js_getStringByKey(innerObj, SYNC_CONFIG_IP);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_IP);
		return PARSER_ERROR;
	}
	syncConfigObj->inFolder.ip = SCStrdup(pstring);

	/* get user */
	pstring = js_getStringByKey(innerObj, SYNC_CONFIG_USER);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_USER);
		return PARSER_ERROR;
	}
	syncConfigObj->inFolder.username = SCStrdup(pstring);

	/* get passwd */
	pstring = js_getStringByKey(innerObj, SYNC_CONFIG_PASSWD);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_PASSWD);
		return PARSER_ERROR;
	}
	syncConfigObj->inFolder.password = SCStrdup(pstring);

	return PARSER_OK;
}

/************************************************************
*Function    : getOuterConfig
*Action      : get outer config information
*Input       : jobj             json object
*Output      : syncConfigObj    config information
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static int getOuterConfig(struct json_object *jobj, SHARE_SYNC_PARA *syncConfigObj)
{
	int ret;
	const char *pstring = NULL;
	struct json_object *outerObj = NULL;

	/* get outer value */
	ret = json_object_object_get_ex(jobj, SYNC_CONFIG_OUTER_NAME, &outerObj);
	if ((!ret) || (NULL == outerObj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_OUTER_NAME);
		return PARSER_ERROR;
	}

	/* get dir */
	pstring = js_getStringByKey(outerObj, SYNC_CONFIG_DIR);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_DIR);
		return PARSER_ERROR;
	}
	syncConfigObj->outFolder.folderName = SCStrdup(pstring);

	/* get ip */
	pstring = js_getStringByKey(outerObj, SYNC_CONFIG_IP);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_IP);
		return PARSER_ERROR;
	}
	syncConfigObj->outFolder.ip = SCStrdup(pstring);

	/* get user */
	pstring = js_getStringByKey(outerObj, SYNC_CONFIG_USER);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_USER);
		return PARSER_ERROR;
	}
	syncConfigObj->outFolder.username = SCStrdup(pstring);

	/* get passwd */
	pstring = js_getStringByKey(outerObj, SYNC_CONFIG_PASSWD);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_PASSWD);
		return PARSER_ERROR;
	}
	syncConfigObj->outFolder.password = SCStrdup(pstring);

	return PARSER_OK;
}

/************************************************************
*Function    : getExtendConfig
*Action      : get extend config information
*Input       : jobj             json object
*Output      : syncConfigObj    config information
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static int getExtendConfig(struct json_object *jobj, SHARE_SYNC_PARA *syncConfigObj)
{
	int ret;
	int value;
	const char *pstring = NULL;
	struct json_object *extendObj = NULL;

	/* get extend value */
	ret = json_object_object_get_ex(jobj, SYNC_CONFIG_EXTEND_NAME, &extendObj);
	if ((!ret) || (NULL == extendObj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_EXTEND_NAME);
		return PARSER_ERROR;
	}

	/* get dst detect flag */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_DETECT_DST);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.isDetectDst = value;

	/* get delete source file flag */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_DEL_SRC_FILE);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.isDelSrcFile = value;

	/* get delete source directory flag */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_DEL_SRC_DIR);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.isDelSrcDir = value;

	/* get av flag */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_AV_NAME);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.isVirusScan = value;

	/* get changename */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_CHANGE_NAME);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.isChangeName = value;

	/* get syncdel */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_SYNCDEL);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.isDeleteSync = value;

	/* get tasktype */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_TASKTYPE);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.planType = value;

	/* get timeval */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_TIMEVAL);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.intervalTime = value;

	/* get synctype */
	value = js_getIntByKey(extendObj, SYNC_CONFIG_SYNCTYPE);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.syncType = value;

	/* get filesuffix */
	pstring = js_getStringByKey(extendObj, SYNC_CONFIG_FILESUFFIX);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_FILESUFFIX);
		return PARSER_ERROR;
	}
	syncConfigObj->extendPara.syncTypeBuff = SCStrdup(pstring);

	return PARSER_OK;
}

/************************************************************
*Function    : analySyncAddJson
*Action      : analy json string
*Input       : jobj             json object
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
			   PARSER_USED  USED
			   PARSER_BUSY  BUSY
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static int analySyncAddJson(struct json_object *jobj)
{
	int ret;
	int len;
	int value;
	const char *pstring = NULL;
	SHARE_SYNC_PARA *pconfig = NULL;

	/* SCMalloc memory */
	len = sizeof(SHARE_SYNC_PARA);
	pconfig = (SHARE_SYNC_PARA *)SCMalloc(len);
	if (NULL == pconfig)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)!", __func__, __LINE__, len);
		return PARSER_ERROR;
	}
	memset(pconfig, 0, len);

	/* get taskName */
	pstring = js_getStringByKey(jobj, SYNC_CONFIG_TASK_NAME);
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, SYNC_CONFIG_TASK_NAME);
		freeConfigObj(pconfig);
		return PARSER_ERROR;
	}
	pconfig->taskName = SCStrdup(pstring);

	/* get switch */
	value = js_getIntByKey(jobj, SYNC_CONFIG_SWITCH);
	if (-1 == value)
	{
		pconfig->configState = SYNC_CONFIG_VALID;
	}
	else
	{
		pconfig->configState = value;
	}

	/* get direction */
	value = js_getIntByKey(jobj, SYNC_CONFIG_DIRECTION);
	if (-1 == value)
	{
		freeConfigObj(pconfig);
		return PARSER_ERROR;
	}
	pconfig->direction = value;

	/* get inner config */
	if (PARSER_OK != getInnerConfig(jobj, pconfig))
	{
		freeConfigObj(pconfig);
		return PARSER_ERROR;
	}

	/* get outer config */
	if (PARSER_OK != getOuterConfig(jobj, pconfig))
	{
		freeConfigObj(pconfig);
		return PARSER_ERROR;
	}

	/* get extend config */
	if (PARSER_OK != getExtendConfig(jobj, pconfig))
	{
		freeConfigObj(pconfig);
		return PARSER_ERROR;
	}

	/* print sync config */
	SCLogInfo("[%s:%d]\nname:%s\nstate:%d\ndirection:%d\n" \
		"inner(dir:%s ip:%s user:%s passwd:%s)\n" \
		"outer(dir:%s ip:%s user:%s passwd:%s)\n" \
		"extend(detectDst:%d delSrcFile:%d delSrcDir:%d av:%d changename:%d syncdel:%d " \
		"tasktype:%d timeval:%u synctype:%d filesuffix:%s)\n\n",
		__func__, __LINE__,
		pconfig->taskName, pconfig->configState, pconfig->direction,
		pconfig->inFolder.folderName, pconfig->inFolder.ip, pconfig->inFolder.username, pconfig->inFolder.password,
		pconfig->outFolder.folderName, pconfig->outFolder.ip, pconfig->outFolder.username, pconfig->outFolder.password,
		pconfig->extendPara.isDetectDst, pconfig->extendPara.isDelSrcFile, pconfig->extendPara.isDelSrcDir,
		pconfig->extendPara.isVirusScan, pconfig->extendPara.isChangeName,
		pconfig->extendPara.isDeleteSync, pconfig->extendPara.planType,
		pconfig->extendPara.intervalTime, pconfig->extendPara.syncType,
		pconfig->extendPara.syncTypeBuff);

	/* effect */
	pconfig->syncSize = 0;
	pconfig->isFirst = PARSER_BTRUE;
	pconfig->inotifyId = -1;
	pconfig->isSyncSuccess = PARSER_BTRUE;
	pconfig->unchangeInfo.taskNameLen = strlen(pconfig->taskName);
	pconfig->unchangeInfo.outFolderNameLen = strlen(pconfig->outFolder.folderName);
	pconfig->unchangeInfo.inFolderNameLen = strlen(pconfig->inFolder.folderName);
	pconfig->unchangeInfo.extendTypeBuffLen = strlen(pconfig->extendPara.syncTypeBuff);
	pconfig->json = jobj;
	pconfig->timer = NULL;
	if (0 != pthread_mutex_init(&(pconfig->timerLock), NULL))
	{
		SCLogError("[%s:%d]init timer mutex failed!", __func__, __LINE__);
		freeConfigObj(pconfig);
		return PARSER_ERROR;
	}

	ret = addOneConfig(pconfig);
	if (PARSER_OK != ret)
	{
		freeConfigObj(pconfig);
		return ret;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : gap_ctl_sync_add_json
*Action      : add one config
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
DEFUN(gap_ctl_sync_add_json,
	gap_ctl_sync_add_json_cmd,
	"file sync add .JSON",
	"sync command\n"
	"add sync rule.\n"
	"Json format string\n")
{
	int ret;
	char *json_str = NULL;
	struct json_object *jobj = NULL;
	enum json_tokener_error jerror;

	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	json_str = argv_concat(argv, argc, 0);
	jobj = json_tokener_parse_verbose(json_str, &jerror);
	if ((NULL == jobj) || (is_error(jobj)))
	{
		SCLogError("[%s:%d]json_tokener_parse_verbose error=%d", __func__, __LINE__, jerror);
		vty_out(vty, "json_tokener_parse_verbose error=%d%s", jerror, VTY_NEWLINE);
		XFREE(MTYPE_TMP, json_str);
		return CMD_SUCCESS;
	}

	ret = analySyncAddJson(jobj);
	if (PARSER_OK != ret)
	{
		SCLogError("[%s:%d]add file sync config failed!", __func__, __LINE__);
		if (PARSER_BUSY == ret)
		{
			vty_out(vty, "direcotry is busy!%s", VTY_NEWLINE);
		}
		else
		{
			vty_out(vty, "add file sync config failed!%s", VTY_NEWLINE);
		}
		json_object_put(jobj);
		XFREE(MTYPE_TMP, json_str);
		return CMD_SUCCESS;
	}

	XFREE(MTYPE_TMP, json_str);
	SCLogInfo("[%s:%d]add file sync config success.", __func__, __LINE__);
	return CMD_SUCCESS;
}
#endif

#if GAP_DESC("Save sync config")
/************************************************************
*Function    : sync_config_write
*Action      : write config to file
*Input       : null
*Output      : null
*Return      : count of config
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
int sync_config_write(struct vty *vty)
{
	int write = 0;
	SHARE_SYNC_PARA *pos = NULL;

	pthread_rwlock_rdlock(&g_fileSyncLock);
	list_for_each_entry(pos, &g_fileSyncConfig, node)
	{
		vty_out(vty, "file sync add %s%s", JSON_FORMAT_STR_PLAIN(pos->json), VTY_NEWLINE);
		write++;
	}
	pthread_rwlock_unlock(&g_fileSyncLock);
	return write;
}
#endif

static struct cmd_node file_sync_node =
{
	.node = FILE_SYNC_NODE,
	.prompt = "",
	.vtysh = 1
};

void sync_conf_cmd_init(void)
{
	install_element(VIEW_NODE, &gap_ctl_show_sync_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_sync_by_name_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_sync_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_sync_by_name_cmd);

	install_element(CONFIG_NODE, &gap_ctl_sync_set_status_json_cmd);
	install_element(CONFIG_NODE, &gap_ctl_sync_del_json_cmd);
	install_element(CONFIG_NODE, &gap_ctl_sync_add_json_cmd);

	install_node(&file_sync_node, sync_config_write);
}

void sync_cmd_init(void)
{
}

void sync_cmd_exit(void)
{
}

