/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_mail.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.6.14
Description    : mail process
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#include "app_common.h"
#include "svrid.h"
#include "lib/memory.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "parser_tcp.h"
#include "db_mysql.h"
#include "cmd_common.h"
#include "parser_common.h"
#include "parser_mail.h"

static char *g_mailAlphabet = NULL;

static char *g_mailDefaultJsonStr = "{\"valid\":1,\"attachments\":{\"size\":20480,\"suffixs\":[\".*\"]}," \
"\"address\":{\"accounts\":[]}," \
"\"content\":{\"keywords\":[]}}";

static MAIL_CONFIG g_mailConfig =
{
	0,
	0,
	NULL,
	{0, 0, NULL},
	{0, NULL},
	{0, NULL}
};

static char g_mailCodesArr[MAIL_CODE_LEN];

static void mail_initCodes(void)
{
	int i;

	for (i = 0; i < MAIL_CODE_LEN; i++)
	{
		g_mailCodesArr[i] = -1;
	}

	for (i = 'A'; i <= 'Z'; i++)
	{
		g_mailCodesArr[i] = i - 'A';
	}

	for (i = 'a'; i <= 'z'; i++)
	{
		g_mailCodesArr[i] = 26 + i - 'a';
	}

	for (i = '0'; i <= '9'; i++)
	{
		g_mailCodesArr[i] = 52 + i - '0';
	}

	g_mailCodesArr['+'] = 62;
	g_mailCodesArr['/'] = 63;
}

int mail_getDecodeOutlen(char *inbuf, int inlen)
{
	int len;

	len = (((inlen + 3) / 4) * 3) + 1;
	if ((inlen > 0) && (inbuf[inlen - 1] == '='))
	{
		--len;
	}

	if ((inlen > 1) && (inbuf[inlen - 2] == '='))
	{
		--len;
	}

	return len;
}

void mail_decode(char *inbuf, int inlen, char *outbuf, int *outlen)
{
	int ix;
	int value;
	int shift = 0;
	int accum = 0;
	int index = 0;

	for (ix = 0; ix < inlen; ix++)
	{
		value = g_mailCodesArr[inbuf[ix] & 0xFF];
		if (value >= 0)
		{
			accum <<= 6;
			shift += 6;
			accum |= value;
			if (shift >= 8)
			{
				shift -= 8;
				outbuf[index++] = ((accum >> shift) & 0xff);
			}
		}
	}

	outbuf[index] = '\0';
	*outlen = index;

	return;
}

void mail_removeOldFile(char *filePath, MAIL_TYPE mailType)
{
	int len;
	char *command = NULL;

	switch (mailType)
	{
	case MAIL_SMTP:
	{
		if (!(smtp_isSaveAttachment()))
		{
			return;
		}
		break;
	}

	case MAIL_POP3:
	{
		if (!(pop3_isSaveAttachment()))
		{
			return;
		}
		break;
	}

	default:
	{
		return;
		break;
	}
	}

	if (0 == access(filePath, 0))
	{
		len = strlen(filePath);
		command = (char *)SCMalloc(len + 8);        /*<< 8: rm -rf */
		if (NULL == command)
		{
			SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", len + 8, __func__, __LINE__);
			return;
		}
		snprintf(command, len + 8, "rm -f %s", filePath);
		(void)cmd_system_novty(command);
		SCFree(command);
		command = NULL;
	}
	return;
}


int mail_writeDataToFile(MAIL_SESSION *session, MAIL_TYPE mailType, char *data, int len)
{
	int writeLen;

	switch (mailType)
	{
	case MAIL_SMTP:
	{
		if (!(smtp_isSaveAttachment()))
		{
			return PARSER_OK;
		}
		break;
	}

	case MAIL_POP3:
	{
		if (!(pop3_isSaveAttachment()))
		{
			return PARSER_OK;
		}
		break;
	}

	default:
	{
		return PARSER_OK;
		break;
	}
	}

	//SCLogInfo("write data length(%d), fp(%p)[%s:%d]", len, session->fp, __func__, __LINE__);
	while (1)
	{
		writeLen = fwrite(data, 1, len, session->fp);
		if (writeLen >= len)
		{
			break;
		}

		if (0 == writeLen)
		{
			SCLogError("write file failed[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		if (writeLen < len)
		{
			data += writeLen;
			len -= writeLen;
		}
	}

	return PARSER_OK;
}

char *mail_getConfig(void)
{
	if (g_mailConfig.mailJsonStr)
	{
		return g_mailConfig.mailJsonStr;
	}

	return g_mailDefaultJsonStr;
}

static void mail_freeControlObj(char **obj, int count)
{
	int index;

	for (index = 0; index < count; index++)
	{
		SCFree(obj[index]);
	}

	if (obj)
	{
		SCFree(obj);
	}
}

void mail_setConfig(MAIL_CONFIG *mailConfig)
{
	if (g_mailConfig.mailJsonStr)
	{
		XFREE(MTYPE_TMP, g_mailConfig.mailJsonStr);
	}
	mail_freeControlObj(g_mailConfig.attachConfig.suffixs, g_mailConfig.attachConfig.suffixCount);
	mail_freeControlObj(g_mailConfig.accountConfig.accounts, g_mailConfig.accountConfig.accountCount);
	mail_freeControlObj(g_mailConfig.contentConfig.keywords, g_mailConfig.contentConfig.keywordCount);
	memcpy(&g_mailConfig, mailConfig, sizeof(MAIL_CONFIG));
}

void mail_freeObjMemory(MAIL_CONFIG *mailConfig)
{
	mail_freeControlObj(g_mailConfig.attachConfig.suffixs, g_mailConfig.attachConfig.suffixCount);
	mail_freeControlObj(g_mailConfig.accountConfig.accounts, g_mailConfig.accountConfig.accountCount);
	mail_freeControlObj(g_mailConfig.contentConfig.keywords, g_mailConfig.contentConfig.keywordCount);
	SCFree(mailConfig);
}

int mail_isMailSizeValid(int mailSize)
{
	if (0 == g_mailConfig.valid)
	{
		if (MAIL_DEFAULT_SIZE < mailSize)
		{
			SCLogWarning("Invalid mail size, mail size(%d), config mail size(%d)[%s:%d]",
				mailSize, MAIL_DEFAULT_SIZE, __func__, __LINE__);
			return PARSER_BFALSE;
		}
		return PARSER_BTRUE;
	}

	if (NULL == g_mailConfig.mailJsonStr)
	{
		if (MAIL_DEFAULT_SIZE < mailSize)
		{
			SCLogWarning("Invalid mail size, mail size(%d), config mail size(%d)[%s:%d]",
				mailSize, MAIL_DEFAULT_SIZE, __func__, __LINE__);
			return PARSER_BFALSE;
		}
		return PARSER_BTRUE;
	}

	if (g_mailConfig.attachConfig.mailSize < mailSize)
	{
		SCLogWarning("Invalid mail size, mail size(%d), config mail size(%d)[%s:%d]",
			mailSize, g_mailConfig.attachConfig.mailSize, __func__, __LINE__);
		return PARSER_BFALSE;
	}

	return PARSER_BTRUE;
}

int mail_isSuffixValid(char *filePath, int isEncode)
{
	int len;
	int index;
	int inLen;
	int outLen;
	char *pStart = NULL;
	char *inContent = NULL;
	char *outContent = NULL;

	if (0 == g_mailConfig.valid)
	{
		return PARSER_BTRUE;
	}

	if (NULL == g_mailConfig.mailJsonStr)
	{
		return PARSER_BTRUE;
	}

	if (isEncode)
	{
		if (NULL == g_mailAlphabet)
		{
			g_mailAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
			mail_initCodes();
		}

		len = strlen(filePath);
		inLen = strlen(MAIL_ATTACHMENT_PATH);
		inContent = filePath + inLen;
		inLen = len - inLen;
		outLen = mail_getDecodeOutlen(inContent, inLen);
		outContent = (char *)SCMalloc(outLen);
		if (NULL == outContent)
		{
			SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", outLen, __func__, __LINE__);
			return PARSER_BTRUE;
		}

		mail_decode(inContent, inLen, outContent, &outLen);
		outContent[outLen] = '\0';
		pStart = strrchr(outContent, '.');
	}
	else
	{
		pStart = strrchr(filePath, '.');
	}

	if (NULL == pStart)
	{
		/* no suffix */
		for (index = 0; index < g_mailConfig.attachConfig.suffixCount; index++)
		{
			if (!strcmp(g_mailConfig.attachConfig.suffixs[index], "."))
			{
				if (outContent)
				{
					SCFree(outContent);
				}
				return PARSER_BTRUE;
			}
		}
	}
	else
	{
		/* have suffix */
		for (index = 0; index < g_mailConfig.attachConfig.suffixCount; index++)
		{
			if (!strcmp(g_mailConfig.attachConfig.suffixs[index], pStart))
			{
				if (outContent)
				{
					SCFree(outContent);
				}
				return PARSER_BTRUE;
			}
			else if (!strcmp(g_mailConfig.attachConfig.suffixs[index], ".*"))
			{
				if (outContent)
				{
					SCFree(outContent);
				}
				return PARSER_BTRUE;
			}
		}
	}

	if (outContent)
	{
		SCFree(outContent);
	}

	SCLogWarning("Invalid mail suffix(%s)[%s:%d]", filePath, __func__, __LINE__);
	return PARSER_BFALSE;
}

int mail_isAccountValid(char *account)
{
	int index;

	if (0 == g_mailConfig.valid)
	{
		return PARSER_BTRUE;
	}

	if (NULL == g_mailConfig.mailJsonStr)
	{
		return PARSER_BTRUE;
	}

	for (index = 0; index < g_mailConfig.accountConfig.accountCount; index++)
	{
		if (strstr(account, g_mailConfig.accountConfig.accounts[index]))
		{
			SCLogWarning("Invalid mail account(%s)[%s:%d]", g_mailConfig.accountConfig.accounts[index], __func__, __LINE__);
			return PARSER_BFALSE;
		}
	}

	return PARSER_BTRUE;
}

int mail_isContentValid(char *content, char *encoding)
{
	int len;
	int index;
	int outLen;
	char *outContent = NULL;

	if (0 == g_mailConfig.valid)
	{
		return PARSER_BTRUE;
	}

	if (NULL == g_mailConfig.mailJsonStr)
	{
		return PARSER_BTRUE;
	}

	if (NULL == encoding)
	{
		for (index = 0; index < g_mailConfig.contentConfig.keywordCount; index++)
		{
			if (strstr(content, g_mailConfig.contentConfig.keywords[index]))
			{
				SCLogWarning("Invalid mail content, exist keyword(%s)[%s:%d]",
					g_mailConfig.contentConfig.keywords[index], __func__, __LINE__);
				return PARSER_BFALSE;
			}
		}
		return PARSER_BTRUE;
	}

	if (strstr(encoding, "base64"))
	{
		if (NULL == g_mailAlphabet)
		{
			g_mailAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
			mail_initCodes();
		}

		len = strlen(content);
		outLen = mail_getDecodeOutlen(content, len);
		outContent = (char *)SCMalloc(outLen);
		if (NULL == outContent)
		{
			SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", outLen, __func__, __LINE__);
			return PARSER_BTRUE;
		}

		mail_decode(content, len, outContent, &outLen);
		outContent[outLen] = '\0';
		for (index = 0; index < g_mailConfig.contentConfig.keywordCount; index++)
		{
			if (strstr(outContent, g_mailConfig.contentConfig.keywords[index]))
			{
				SCLogWarning("Invalid mail content, exist keyword(%s)[%s:%d]",
					g_mailConfig.contentConfig.keywords[index], __func__, __LINE__);
				SCFree(outContent);
				return PARSER_BFALSE;
			}
		}

		SCFree(outContent);
		outContent = NULL;
	}

	return PARSER_BTRUE;
}

void mail_getFilenameFullPath(char *path, char *fileName, int fileNameLen, int *isEncode)
{
	int len;
	int offset;
	char *startAddr = NULL;
	char *endAddr = NULL;

	offset = fileNameLen;
	while (offset--)
	{
		if (endAddr)
		{
			if ('?' == *(fileName + offset - 1))
			{
				startAddr = fileName + offset - 1;
				break;
			}
		}
		else
		{
			if ('?' == *(fileName + offset - 1))
			{
				endAddr = fileName + offset - 1;
			}
		}
	}

	len = strlen(path);
	if (startAddr)
	{
		*isEncode = PARSER_BTRUE;
		offset = endAddr - startAddr - 1;
		if (offset)
		{
			memcpy(path + len, startAddr + 1, offset);
		}
	}
	else if (endAddr)
	{
		*isEncode = PARSER_BTRUE;
		offset = endAddr - fileName;
		if (offset)
		{
			memcpy(path + len, fileName, offset);
		}
	}
	else
	{
		*isEncode = PARSER_BFALSE;
		memcpy(path + len, fileName, fileNameLen);
	}


	return;
}

void mail_replaceUnknowChar(char *filePath)
{
	int len;
	char *startAddr = NULL;

	len = strlen(MAIL_ATTACHMENT_PATH);
	startAddr = filePath + len;
	while (*startAddr)
	{
		if (('.' != *startAddr) && ('=' != *startAddr) && ('_' != *startAddr) && (!isalnum(*startAddr)))
		{
			*startAddr = '_';
		}
		startAddr++;
	}
	return;
}

PROTOCOL_FILTER_DEFINE(mail, _SVR_ID_COUNT, NULL, NULL, NULL, NULL)

PROTOCOL_FILTER_OP(mail)



