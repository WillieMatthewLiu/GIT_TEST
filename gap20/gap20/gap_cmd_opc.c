/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : gap_cmd_opc.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.6.14
Description    : opc vty
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
#include "parser_opc.h"
#include "gap_cmd_group.h"
#include "gap_cmd_opc.h"

/************************************************************
*Function    : gap_ctl_show_opc_by_name
*Action      : display one task config info
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.6.20
*Instruction : null
************************************************************/
DEFUN(gap_ctl_show_opc_by_name,
	gap_ctl_show_opc_by_name_cmd,
	"show opc NAME",
	SHOW_STR
	"opc\n"
	"name\n")
{
	OPC_CONFIG_INFO *opcConfig = NULL;

	opcConfig = (OPC_CONFIG_INFO *)get_protocol_rule(argv[0], SVR_ID_OPC);
	if (opcConfig)
	{
		if (opcConfig->jstr)
		{
			vty_out(vty, "%s%s", opcConfig->jstr, VTY_NEWLINE);
		}
	}
	return CMD_SUCCESS;
}

/************************************************************
*Function    : gap_ctl_show_opc
*Action      : display all task config info
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
DEFUN(gap_ctl_show_opc,
	gap_ctl_show_opc_cmd,
	"show opc",
	SHOW_STR
	"opc\n")
{
	OPC_CONFIG_INFO *opcConfig = NULL;

	list_for_each_entry(opcConfig, &g_opcConfigHead, topList)
	{
		if (opcConfig->jstr)
		{
			vty_out(vty, "%s%s", opcConfig->jstr, VTY_NEWLINE);
		}
	}
	return CMD_SUCCESS;
}

/************************************************************
*Function    : gap_ctl_opc_del_json
*Action      : delete on config
*Input       : null
*Output      : null
*Return      : CMD_SUCCESS
			   CMD_ERR_NOTHING_TODO
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
DEFUN(gap_ctl_opc_del_json,
	gap_ctl_opc_del_json_cmd,
	"no opc NAME",
	NO_STR
	"opc\n"
	"name\n")
{
	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	opc_delConfig(argv[0]);

	SCLogInfo("[%s:%d]delete opc config success, group name(%s)", __func__, __LINE__, argv[0]);
	return CMD_SUCCESS;
}

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
*Function    : opc_analyAddJson
*Action      : analy json string
*Input       : jobj             json object
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.6.15
*Instruction : null
************************************************************/
static int opc_analyAddJson(struct json_object *opcJobj, char *jstr)
{
	int size;
	int value;
	const char *pstring = NULL;
	OPC_CONFIG_INFO *opcConfig = NULL;

	size = sizeof(OPC_CONFIG_INFO);
	opcConfig = (OPC_CONFIG_INFO *)SCMalloc(size);
	if (NULL == opcConfig)
	{
		SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", size, __func__, __LINE__);
		return PARSER_ERROR;
	}
	memset(opcConfig, 0, size);

	opcConfig->jstr = jstr;

	/* get group name */
	pstring = js_getStringByKey(opcJobj, OPC_CONFIG_GROUP_NAME);
	if (NULL == pstring)
	{
		return PARSER_ERROR;
	}
	opcConfig->groupName = SCStrdup(pstring);

	/* get mode */
	value = js_getIntByKey(opcJobj, OPC_CONFIG_MODE);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	opcConfig->mode = value;

	/* get valid flag */
	value = js_getIntByKey(opcJobj, OPC_CONFIG_VALID);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	opcConfig->valid = value;

	/* print opc config */
	SCLogInfo("[%s:%d]\ngroupName:%s\nmode:%d\nvalid:%d\n\n",
		__func__, __LINE__, opcConfig->groupName,
		opcConfig->mode, opcConfig->valid);

	/* add opc config */
	if (PARSER_OK != opc_addConfig(opcConfig))
	{
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : gap_ctl_add_opc_json
*Action      : add opc config
*Input       : null
*Output      : null
*Return      : CMD_SUCCESS
			   CMD_ERR_NOTHING_TODO
*Author      : liuzongquan(000932)
*Date        : 2017.6.21
*Instruction : null
************************************************************/
DEFUN(gap_ctl_add_opc_json,
	gap_ctl_add_opc_json_cmd,
	"opc add .JSON",
	"opc command\n"
	"add opc rule.\n"
	"Json format string\n")
{
	int ret;
	char *jstr = NULL;
	struct json_object *opcJobj = NULL;
	enum json_tokener_error jerror;

	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	jstr = argv_concat(argv, argc, 0);
	opcJobj = json_tokener_parse_verbose(jstr, &jerror);
	if ((NULL == opcJobj) || (is_error(opcJobj)))
	{
		SCLogError("[%s:%d]json_tokener_parse_verbose error=%d", __func__, __LINE__, jerror);
		vty_out(vty, "json_tokener_parse_verbose error=%d%s", jerror, VTY_NEWLINE);
		XFREE(MTYPE_TMP, jstr);
		return CMD_SUCCESS;
	}

	ret = opc_analyAddJson(opcJobj, jstr);
	if (PARSER_OK != ret)
	{
		SCLogError("[%s:%d]add opc config failed!", __func__, __LINE__);
		vty_out(vty, "add opc config failed!%s", VTY_NEWLINE);
		json_object_put(opcJobj);
		XFREE(MTYPE_TMP, jstr);
		return CMD_SUCCESS;
	}

	json_object_put(opcJobj);
	SCLogInfo("[%s:%d]add opc config success.", __func__, __LINE__);
	return CMD_SUCCESS;
}

static struct cmd_node opc_node =
{
	.node = OPC_NODE,
	.prompt = "",
	.vtysh = 1
};

static int opc_config_write(struct vty *vty)
{
	int write = 0;
	OPC_CONFIG_INFO *opcConfig = NULL;

	list_for_each_entry(opcConfig, &g_opcConfigHead, topList)
	{
		if (opcConfig->jstr)
		{
			vty_out(vty, "opc add %s%s", opcConfig->jstr, VTY_NEWLINE);
			write++;
		}
	}
	return write;
}

void opc_conf_cmd_init(void)
{
	install_element(VIEW_NODE, &gap_ctl_show_opc_by_name_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_opc_by_name_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_opc_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_opc_cmd);

	install_element(CONFIG_NODE, &gap_ctl_opc_del_json_cmd);
	install_element(CONFIG_NODE, &gap_ctl_add_opc_json_cmd);

	install_node(&opc_node, opc_config_write);
}

void opc_cmd_init(void)
{
}

void opc_cmd_exit(void)
{
}


