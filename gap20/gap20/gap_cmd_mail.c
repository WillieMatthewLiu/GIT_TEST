/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : gap_cmd_mail.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.6.14
Description    : mail vty
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
//#include "command.h"
#include "lib/memory.h"
#include "gap_cmd.h"
#include "gap_ctl.h"
#include "gap_ctl_ha.h"
#include "gap_ctl_conf.h"
#include "gap_ctl_adapter.h"
#include "parser_common.h"
#include "parser_mail.h"
#include "gap_cmd_mail.h"

/************************************************************
*Function    : gap_ctl_show_mail
*Action      : display mail config info
*Input       : null
*Output      : null
*Return      : CMD_SUCCESS
*Author      : liuzongquan(000932)
*Date        : 2017.6.14
*Instruction : null
************************************************************/
DEFUN(gap_ctl_show_mail,
	gap_ctl_show_mail_cmd,
	"show mail",
	SHOW_STR
	"mail\n")
{
	vty_out(vty, "%s%s", mail_getConfig(), VTY_NEWLINE);
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
*Function    : js_getStringById
*Action      : get json string string value of id
*Input       : jobj     json object
			   id       id
*Output      : null
*Return      : value
*Author      : liuzongquan(000932)
*Date        : 2017.6.15
*Instruction : null
************************************************************/
static const char *js_getStringById(struct json_object *jobj, int id)
{
	struct json_object *pval = NULL;

	pval = json_object_array_get_idx(jobj, id);
	if (NULL == pval)
	{
		SCLogError("[%s:%d]get json object of id(%d) failed", __func__, __LINE__, id);
		return NULL;
	}

	return json_object_get_string(pval);
}

/************************************************************
*Function    : getAttachmentConfig
*Action      : get attachment config information
*Input       : mailJobj     json object
*Output      : mailConfig   mail config
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.6.15
*Instruction : null
************************************************************/
static int getAttachmentConfig(struct json_object *mailJobj, MAIL_CONFIG *mailConfig)
{
	int ret;
	int value;
	int index;
	char *nstring = NULL;
	const char *pstring = NULL;
	struct json_object *attachJobj = NULL;
	struct json_object *suffixJobj = NULL;

	/* get attachment json obj */
	ret = json_object_object_get_ex(mailJobj, MAIL_CONFIG_ATTACH, &attachJobj);
	if ((!ret) || (NULL == attachJobj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, MAIL_CONFIG_ATTACH);
		return PARSER_ERROR;
	}

	/* get size(KB) */
	value = js_getIntByKey(attachJobj, MAIL_CONFIG_SIZE);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	mailConfig->attachConfig.mailSize = (value * PARSER_BYTE_PER_KB);

	/* get suffix json obj */
	ret = json_object_object_get_ex(attachJobj, MAIL_CONFIG_SUFFIXS, &suffixJobj);
	if ((!ret) || (NULL == suffixJobj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, MAIL_CONFIG_SUFFIXS);
		return PARSER_ERROR;
	}

	/* get suffix number */
	mailConfig->attachConfig.suffixCount = json_object_array_length(suffixJobj);

	/* get suffixs memory */
	if (mailConfig->attachConfig.suffixCount)
	{
		mailConfig->attachConfig.suffixs = (char **)SCMalloc(mailConfig->attachConfig.suffixCount * sizeof(char *));
		if (NULL == mailConfig->attachConfig.suffixs)
		{
			SCLogError("SCMalloc memory failed, size(%d)[%s:%d]",
				(mailConfig->attachConfig.suffixCount * (int)sizeof(char *)), __func__, __LINE__);
			return PARSER_ERROR;
		}
	}

	/* get suffixs */
	for (index = 0; index < mailConfig->attachConfig.suffixCount; index++)
	{
		pstring = js_getStringById(suffixJobj, index);
		if (NULL == pstring)
		{
			SCLogError("[%s:%d]not find id(%d)", __func__, __LINE__, index);
			return PARSER_ERROR;
		}

		nstring = SCStrdup(pstring);
		if (NULL == nstring)
		{
			SCLogError("SCStrdup memory failed, content(%s)[%s:%d]", pstring, __func__, __LINE__);
			return PARSER_ERROR;
		}

		mailConfig->attachConfig.suffixs[index] = nstring;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : getAddressConfig
*Action      : get address config information
*Input       : mailJobj     json object
*Output      : mailConfig   mail config
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.6.15
*Instruction : null
************************************************************/
static int getAddressConfig(struct json_object *mailJobj, MAIL_CONFIG *mailConfig)
{
	int ret;
	int index;
	char *nstring = NULL;
	const char *pstring = NULL;
	struct json_object *addressJobj = NULL;
	struct json_object *accountJobj = NULL;

	/* get address json obj */
	ret = json_object_object_get_ex(mailJobj, MAIL_CONFIG_ADDRESS, &addressJobj);
	if ((!ret) || (NULL == addressJobj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, MAIL_CONFIG_ADDRESS);
		return PARSER_ERROR;
	}

	/* get account json obj */
	ret = json_object_object_get_ex(addressJobj, MAIL_CONFIG_ACCOUNTS, &accountJobj);
	if ((!ret) || (NULL == accountJobj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, MAIL_CONFIG_ACCOUNTS);
		return PARSER_ERROR;
	}

	/* get account number */
	mailConfig->accountConfig.accountCount = json_object_array_length(accountJobj);

	/* get accounts memory */
	if (mailConfig->accountConfig.accountCount)
	{
		mailConfig->accountConfig.accounts = (char **)SCMalloc(mailConfig->accountConfig.accountCount * sizeof(char *));
		if (NULL == mailConfig->accountConfig.accounts)
		{
			SCLogError("SCMalloc memory failed, size(%d)[%s:%d]",
				(mailConfig->accountConfig.accountCount * (int)sizeof(char *)), __func__, __LINE__);
			return PARSER_ERROR;
		}
	}

	/* get accounts */
	for (index = 0; index < mailConfig->accountConfig.accountCount; index++)
	{
		pstring = js_getStringById(accountJobj, index);
		if (NULL == pstring)
		{
			SCLogError("[%s:%d]not find id(%d)", __func__, __LINE__, index);
			return PARSER_ERROR;
		}

		nstring = SCStrdup(pstring);
		if (NULL == nstring)
		{
			SCLogError("SCStrdup memory failed, content(%s)[%s:%d]", pstring, __func__, __LINE__);
			return PARSER_ERROR;
		}

		mailConfig->accountConfig.accounts[index] = nstring;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : getContentConfig
*Action      : get content config information
*Input       : mailJobj     json object
*Output      : mailConfig   mail config
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.6.15
*Instruction : null
************************************************************/
static int getContentConfig(struct json_object *mailJobj, MAIL_CONFIG *mailConfig)
{
	int ret;
	int index;
	char *nstring = NULL;
	const char *pstring = NULL;
	struct json_object *contentJobj = NULL;
	struct json_object *keywordJobj = NULL;

	/* get content json obj */
	ret = json_object_object_get_ex(mailJobj, MAIL_CONFIG_CONTENT, &contentJobj);
	if ((!ret) || (NULL == contentJobj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, MAIL_CONFIG_CONTENT);
		return PARSER_ERROR;
	}

	/* get keyword json obj */
	ret = json_object_object_get_ex(contentJobj, MAIL_CONFIG_KEYWORDS, &keywordJobj);
	if ((!ret) || (NULL == keywordJobj))
	{
		SCLogError("[%s:%d]not find key(%s)", __func__, __LINE__, MAIL_CONFIG_KEYWORDS);
		return PARSER_ERROR;
	}

	/* get account number */
	mailConfig->contentConfig.keywordCount = json_object_array_length(keywordJobj);

	/* get keywords memory */
	if (mailConfig->contentConfig.keywordCount)
	{
		mailConfig->contentConfig.keywords = (char **)SCMalloc(mailConfig->contentConfig.keywordCount * sizeof(char *));
		if (NULL == mailConfig->contentConfig.keywords)
		{
			SCLogError("SCMalloc memory failed, size(%d)[%s:%d]",
				(mailConfig->contentConfig.keywordCount * (int)sizeof(char *)), __func__, __LINE__);
			return PARSER_ERROR;
		}
	}

	/* get keywords */
	for (index = 0; index < mailConfig->contentConfig.keywordCount; index++)
	{
		pstring = js_getStringById(keywordJobj, index);
		if (NULL == pstring)
		{
			SCLogError("[%s:%d]not find id(%d)", __func__, __LINE__, index);
			return PARSER_ERROR;
		}

		nstring = SCStrdup(pstring);
		if (NULL == nstring)
		{
			SCLogError("SCStrdup memory failed, content(%s)[%s:%d]", pstring, __func__, __LINE__);
			return PARSER_ERROR;
		}

		mailConfig->contentConfig.keywords[index] = nstring;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : mail_analySetJson
*Action      : analy json string
*Input       : jobj             json object
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.6.15
*Instruction : null
************************************************************/
static int mail_analySetJson(struct json_object *mailJobj, char *jstr)
{
	int size;
	int value;
	MAIL_CONFIG *mailConfig = NULL;

	size = sizeof(MAIL_CONFIG);
	mailConfig = (MAIL_CONFIG *)SCMalloc(size);
	if (NULL == mailConfig)
	{
		SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", size, __func__, __LINE__);
		return PARSER_ERROR;
	}
	memset(mailConfig, 0, size);

	/* get jstr */
	mailConfig->mailJsonStr = jstr;

	/* get valid flag */
	value = js_getIntByKey(mailJobj, MAIL_CONFIG_VALID);
	if (-1 == value)
	{
		return PARSER_ERROR;
	}
	mailConfig->valid = value;

	/* get attachment config */
	if (PARSER_OK != getAttachmentConfig(mailJobj, mailConfig))
	{
		mail_freeObjMemory(mailConfig);
		return PARSER_ERROR;
	}

	/* get address config */
	if (PARSER_OK != getAddressConfig(mailJobj, mailConfig))
	{
		mail_freeObjMemory(mailConfig);
		return PARSER_ERROR;
	}

	/* get content config */
	if (PARSER_OK != getContentConfig(mailJobj, mailConfig))
	{
		mail_freeObjMemory(mailConfig);
		return PARSER_ERROR;
	}

	/* print mail config */
	SCLogInfo("[%s:%d]\nvalid:%d, mailJsonStr:%p\n" \
		"attachments(size:%d suffixCount:%d suffixs:%s%s)\n" \
		"address(accountCount:%d accounts:%s%s)\n" \
		"content(keywordCount:%d keywords:%s%s)\n\n",
		__func__, __LINE__,
		mailConfig->valid, mailConfig->mailJsonStr,
		mailConfig->attachConfig.mailSize, mailConfig->attachConfig.suffixCount,
		(mailConfig->attachConfig.suffixCount) ? mailConfig->attachConfig.suffixs[0] : "",
		(1 < mailConfig->attachConfig.suffixCount) ? ", ..." : "",
		mailConfig->accountConfig.accountCount,
		(mailConfig->accountConfig.accountCount) ? mailConfig->accountConfig.accounts[0] : "",
		(1 < mailConfig->accountConfig.accountCount) ? ", ..." : "",
		mailConfig->contentConfig.keywordCount,
		(mailConfig->contentConfig.keywordCount) ? mailConfig->contentConfig.keywords[0] : "",
		(1 < mailConfig->contentConfig.keywordCount) ? ", ..." : "");

	/* set mail config */
	mailConfig->reserve = 0;
	mail_setConfig(mailConfig);
	SCFree(mailConfig);
	return PARSER_OK;
}

/************************************************************
*Function    : gap_ctl_set_mail_json
*Action      : set mail config
*Input       : null
*Output      : null
*Return      : CMD_SUCCESS
			   CMD_ERR_NOTHING_TODO
*Author      : liuzongquan(000932)
*Date        : 2017.6.15
*Instruction : null
************************************************************/
DEFUN(gap_ctl_set_mail_json,
	gap_ctl_set_mail_json_cmd,
	"mail set .JSON",
	"mail command\n"
	"set mail rule.\n"
	"Json format string\n")
{
	int ret;
	char *jstr = NULL;
	struct json_object *mailJobj = NULL;
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
	mailJobj = json_tokener_parse_verbose(jstr, &jerror);
	if ((NULL == mailJobj) || (is_error(mailJobj)))
	{
		SCLogError("[%s:%d]json_tokener_parse_verbose error=%d", __func__, __LINE__, jerror);
		vty_out(vty, "json_tokener_parse_verbose error=%d%s", jerror, VTY_NEWLINE);
		XFREE(MTYPE_TMP, jstr);
		return CMD_SUCCESS;
	}

	ret = mail_analySetJson(mailJobj, jstr);
	if (PARSER_OK != ret)
	{
		SCLogError("[%s:%d]set mail config failed!", __func__, __LINE__);
		vty_out(vty, "set mail config failed!%s", VTY_NEWLINE);
		json_object_put(mailJobj);
		XFREE(MTYPE_TMP, jstr);
		return CMD_SUCCESS;
	}

	json_object_put(mailJobj);
	SCLogInfo("[%s:%d]add file sync config success.", __func__, __LINE__);
	return CMD_SUCCESS;
}

static struct cmd_node mail_node =
{
	.node = MAIL_NODE,
	.prompt = "",
	.vtysh = 1
};

static int mail_config_write(struct vty *vty)
{
	vty_out(vty, "mail set %s%s", mail_getConfig(), VTY_NEWLINE);
	return CMD_SUCCESS;
}

void mail_conf_cmd_init(void)
{
	install_element(VIEW_NODE, &gap_ctl_show_mail_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_mail_cmd);

	install_element(CONFIG_NODE, &gap_ctl_set_mail_json_cmd);

	install_node(&mail_node, mail_config_write);
}

void mail_cmd_init(void)
{
}

void mail_cmd_exit(void)
{
}


