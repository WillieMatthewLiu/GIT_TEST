/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_smtp.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.5.31
Description    : smtp protocol process
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
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gap_stgy.h"
#include "gapconfig.h"
#include "parser_tcp.h"
#include "db_mysql.h"
#include "cmd_common.h"
#include "parser_common.h"
#include "parser_mail.h"

/* Mail key */
MAIL_KEY_INFO g_mailKeyInfo[MAIL_KEY_BUTT] =
{
	{5,  "EHLO "},
	{5,  "AUTH "},
	{5,  "USER "},
	{5,  "PASS "},
	{4,  "STAT"},
	{4,  "LIST"},
	{4,  "UIDL"},
	{5,  "RETR "},
	{11, "MAIL FROM: "},
	{9,  "RCPT TO: "},
	{4,  "DATA"},
	{4,  "QUIT"},
	{5,  "SIZE="},
	{9,  "Subject: "},
	{27, "Content-Transfer-Encoding: "},
	{10, "filename=\""},
	{4,  "+OK "},
	{6,  "From: "},
	{4,  "To: "},
	{4,  "Cc: "}
};

/* Configure data */
static MAIL_INDEPENDENT_CONFIG g_smtpConfig;

/************************************************************
*Function    : smtp_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static MAIL_SESSION *smtp_allocSession(void)
{
	MAIL_SESSION *session = NULL;

	session = SCMalloc(sizeof(MAIL_SESSION));
	if (NULL == session)
	{
		SCLogError("SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)sizeof(MAIL_SESSION), __func__, __LINE__);
		return NULL;
	}
	memset(session, 0, sizeof(*session));
	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("evbuffer_new failed[%s:%d]", __func__, __LINE__);
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("evbuffer_new failed[%s:%d]", __func__, __LINE__);
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->isValid = PARSER_BFALSE;
	session->connecting = MAIL_DISCONNECT;
	session->isStartMail = PARSER_BFALSE;
	session->isCheckSubject = PARSER_BFALSE;
	session->isCheckContent = PARSER_BFALSE;
	session->mailSize = 0;
	session->analySize = 0;
	session->fp = NULL;
	session->contentEncode = NULL;
	session->attachmentEncode = NULL;
	return session;
}

/************************************************************
*Function    : smtp_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void smtp_freeSession(MAIL_SESSION *session)
{
	if (session->fp)
	{
		//SCLogInfo("close fp(%p)[%s:%d]", session->fp, __func__, __LINE__);
		fclose(session->fp);
		session->fp = NULL;
	}

	evbuffer_free(session->rspBuf);
	session->rspBuf = NULL;
	evbuffer_free(session->reqBuf);
	session->reqBuf = NULL;
	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : smtp_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void smtp_writeSeceventLog(struct filter_header *hdr, int packLen, char *content)
{
	char sourceIp[MAIL_IP_BUFF_SIZE];
	char destIp[MAIL_IP_BUFF_SIZE];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;

	addr2str(hdr->ip->saddr, sourceIp);
	addr2str(hdr->ip->daddr, destIp);
	proto = (char*)server_strfromid(SVR_ID_SMTP);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);

	INSERT_ACCESSAUDIT_LOG(autoId, sourceIp, destIp, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
		aclData->user, "none", l_critical, aclData->groupname, "false", packLen, content);
}

/************************************************************
*Function    : smtp_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET smtp_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	MAIL_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogError("invalid para, hdr(%p), user(%p), maybe session is closed[%s:%d]", hdr, hdr->user, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		smtp_writeSeceventLog(hdr, packLen, content);
	}

	session = hdr->user;

	SCLogInfo("on socket close, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);

	smtp_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

int smtp_isSaveAttachment(void)
{
	return g_smtpConfig.isSaveAttachment;
}

#if GAP_DESC("client request message")
static int smtp_checkMailBodySeg(struct filter_header *hdr, MAIL_SESSION *session, char *data, int len)
{
	int offset;
	int isEncode;
	char *filePath = NULL;
	char *startAddr = NULL;
	char *endAddr = NULL;
	char *pSubject = NULL;

	if (!(session->isCheckSubject))
	{
		if (NULL == strstr(data, g_mailKeyInfo[MAIL_POP3_FROM].key))
		{
			return PARSER_OK;
		}

		startAddr = strstr(data, g_mailKeyInfo[MAIL_SUBJECT].key);
		if (startAddr)
		{
			startAddr += g_mailKeyInfo[MAIL_SUBJECT].len;
			endAddr = strchr(startAddr, '\r');
			if (NULL == endAddr)
			{
				endAddr = strchr(startAddr, '\n');
				if (NULL == endAddr)
				{
					endAddr = strchr(startAddr, '\0');
				}
			}

			if (endAddr)
			{
				offset = (int)(endAddr - startAddr) + 1;
				pSubject = (char *)SCMalloc(offset);
				if (NULL == pSubject)
				{
					SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset, __func__, __LINE__);
					return PARSER_ERROR;
				}
				memcpy(pSubject, startAddr, offset);
				pSubject[offset - 1] = '\0';
				SCLogInfo("Subject:%s[%s:%d]", pSubject, __func__, __LINE__);
				if (!mail_isContentValid(pSubject, NULL))
				{
					SCFree(pSubject);
					return PARSER_ERROR;
				}
				SCFree(pSubject);
				pSubject = NULL;
			}
		}
		session->isCheckSubject = PARSER_BTRUE;
	}
	else if (!(session->isCheckContent))
	{
		if (session->contentEncode)
		{
			if (!strncmp(data, "\r\n----", MAIL_NO_CONTENT_END_LEN))
			{
				session->isCheckContent = PARSER_BTRUE;
				return PARSER_OK;
			}

			while (len--)
			{
				if (('\r' == data[len - 1]) || ('\n' == data[len - 1]))
				{
					data[len - 1] = '\0';
				}
				else
				{
					break;
				}
			}
			SCLogInfo("Content:%s[%s:%d]", data, __func__, __LINE__);
			if (!mail_isContentValid(data, session->contentEncode))
			{
				SCFree(pSubject);
				return PARSER_ERROR;
			}
			session->isCheckContent = PARSER_BTRUE;
			SCFree(session->contentEncode);
			session->contentEncode = NULL;
		}
		else
		{
			startAddr = strstr(data, g_mailKeyInfo[MAIL_ENCODING].key);
			if (startAddr)
			{
				startAddr += g_mailKeyInfo[MAIL_ENCODING].len;
				endAddr = strchr(startAddr, '\r');
				if (NULL == endAddr)
				{
					endAddr = strchr(startAddr, '\n');
					if (NULL == endAddr)
					{
						endAddr = strchr(startAddr, '\0');
					}
				}

				if (endAddr)
				{
					offset = (int)(endAddr - startAddr) + 1;
					session->contentEncode = (char *)SCMalloc(offset);
					if (NULL == session->contentEncode)
					{
						SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset, __func__, __LINE__);
						return PARSER_ERROR;
					}
					memcpy(session->contentEncode, startAddr, offset);
					session->contentEncode[offset - 1] = '\0';
					SCLogInfo("contentEncode:%s[%s:%d]", session->contentEncode, __func__, __LINE__);
				}
			}
		}
	}
	else
	{
		startAddr = strstr(data, g_mailKeyInfo[MAIL_FILENAME].key);
		if (startAddr)
		{
			startAddr += g_mailKeyInfo[MAIL_FILENAME].len;
			endAddr = strchr(startAddr, '\"');
			if (endAddr)
			{
				offset = (int)(endAddr - startAddr) + MAIL_ATTACHMENT_PATH_LEN;
				filePath = (char *)SCMalloc(offset);
				if (NULL == filePath)
				{
					SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset, __func__, __LINE__);
					return PARSER_ERROR;
				}
				memset(filePath, 0, offset);
				snprintf(filePath, offset, "%s", MAIL_ATTACHMENT_PATH);
				mail_getFilenameFullPath(filePath, startAddr, offset - MAIL_ATTACHMENT_PATH_LEN, &isEncode);
				SCLogInfo("filename(%s)[%s:%d]", filePath, __func__, __LINE__);
				if (!mail_isSuffixValid(filePath, isEncode))
				{
					SCFree(filePath);
					return PARSER_ERROR;
				}
				mail_replaceUnknowChar(filePath);
				mail_removeOldFile(filePath, MAIL_SMTP);

				if (!(smtp_isSaveAttachment()))
				{
					SCFree(filePath);
					filePath = NULL;
					return PARSER_OK;
				}

				session->fp = fopen(filePath, "a+");
				if (NULL == session->fp)
				{
					SCLogError("fopen failed, path(%s)[%s:%d]\n", filePath, __func__, __LINE__);
					SCFree(filePath);
					filePath = NULL;
					return PARSER_ERROR;
				}
				SCFree(filePath);
				filePath = NULL;

				//SCLogInfo("open fp(%p)[%s:%d]", session->fp, __func__, __LINE__);
				startAddr = strstr(data, g_mailKeyInfo[MAIL_ENCODING].key);
				if (startAddr)
				{
					startAddr += g_mailKeyInfo[MAIL_ENCODING].len;
					endAddr = strchr(startAddr, '\r');
					if (NULL == endAddr)
					{
						endAddr = strchr(startAddr, '\n');
					}

					if (endAddr)
					{
						*endAddr = '\0';
						//SCLogInfo("write data length(%d), fp(%p)[%s:%d]", (int)strlen(startAddr), session->fp, __func__, __LINE__);
						fprintf(session->fp, "%s\n", startAddr);
					}
				}
				else
				{
					//SCLogInfo("write data length(%d), fp(%p)[%s:%d]", (int)strlen("unknow-encoding\n"), session->fp, __func__, __LINE__);
					fprintf(session->fp, "unknow-encoding\n");
				}
			}
		}
	}

	return PARSER_OK;
}

static int smtp_getMailHeaderSeg(struct filter_header *hdr, MAIL_SESSION *session, char *data, int len)
{
	int offset;
	int mailSize;
	char *startAddr = NULL;
	char *endAddr = NULL;
	char *pFrom = NULL;
	char *pTo = NULL;

	if (!(session->isValid))
	{
		if ((!strncmp(data, g_mailKeyInfo[MAIL_EHLO].key, g_mailKeyInfo[MAIL_EHLO].len)) || (!strncmp(data, "220 ", 4)))
		{
			session->isValid = PARSER_BTRUE;
			return PARSER_OK;
		}

		SCLogError("Invalid data format[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (!strncmp(data, g_mailKeyInfo[MAIL_FROM].key, g_mailKeyInfo[MAIL_FROM].len))
	{
		startAddr = data + g_mailKeyInfo[MAIL_FROM].len;
		endAddr = strchr(startAddr, ' ');
		if (endAddr)
		{
			offset = (int)(endAddr - startAddr) + 1;
			pFrom = (char *)SCMalloc(offset);
			if (NULL == pFrom)
			{
				SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset, __func__, __LINE__);
				return PARSER_ERROR;
			}
			memcpy(pFrom, startAddr, offset);
			pFrom[offset - 1] = '\0';
			SCLogInfo("From:%s[%s:%d]", pFrom, __func__, __LINE__);
			if (!mail_isAccountValid(pFrom))
			{
				SCFree(pFrom);
				return PARSER_ERROR;
			}
			SCFree(pFrom);
			pFrom = NULL;

			if (strstr(endAddr, g_mailKeyInfo[MAIL_SIZE].key))
			{
				sscanf(endAddr, "%*[^SIZE=]SIZE=%d[0-9]", &mailSize);
				SCLogInfo("Size:%d[%s:%d]", mailSize, __func__, __LINE__);
				if (!mail_isMailSizeValid(mailSize))
				{
					return PARSER_ERROR;
				}
				session->mailSize = mailSize;
			}
		}
	}
	else if (!strncmp(data, g_mailKeyInfo[MAIL_TO].key, g_mailKeyInfo[MAIL_TO].len))
	{
		startAddr = data + g_mailKeyInfo[MAIL_TO].len;
		endAddr = strchr(startAddr, '\r');
		if (NULL == endAddr)
		{
			endAddr = strchr(startAddr, '\n');
			if (NULL == endAddr)
			{
				endAddr = strchr(startAddr, '\0');
			}
		}

		if (endAddr)
		{
			offset = (int)(endAddr - startAddr) + 1;
			pTo = (char *)SCMalloc(offset);
			if (NULL == pTo)
			{
				SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset, __func__, __LINE__);
				return PARSER_ERROR;
			}
			memcpy(pTo, startAddr, offset);
			pTo[offset - 1] = '\0';
			SCLogInfo("To:%s[%s:%d]", pTo, __func__, __LINE__);
			if (!mail_isAccountValid(pTo))
			{
				SCFree(pTo);
				return PARSER_ERROR;
			}
			SCFree(pTo);
			pTo = NULL;
		}
	}
	else if (!strncmp(data, g_mailKeyInfo[MAIL_DATA].key, g_mailKeyInfo[MAIL_DATA].len))
	{
		session->isStartMail = PARSER_BTRUE;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : smtp_checkCltEventReqbufData
*Action      : check the full session in reqbuf
*Input       : hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int smtp_checkCltEventReqbufData(struct filter_header *hdr, MAIL_SESSION *session)
{
	int offset;
	ev_ssize_t ret;
	size_t reqBufLen;
	struct evbuffer_ptr pos;
	char tmp[MAIL_SMTP_END_LEN];
	char *data = NULL;

	while (1)
	{
		/* Get data length of request eventbuffer */
		reqBufLen = evbuffer_get_length(session->reqBuf);
		if (0 >= reqBufLen)
		{
			break;
		}

		if (session->isStartMail)
		{
			/* Start mail already */
			if (session->fp)
			{
				/* Check data all receive */
				pos = evbuffer_search(session->reqBuf, "\r\n\r\n", MAIL_TWO_WRAP_LEN, NULL);
				if (-1 == pos.pos)
				{
					/* Not find, write data to fp */

					if (session->mailSize < (session->analySize + (int)reqBufLen))
					{
						SCLogError("mail content analy failed, mail size:%d, analy size:%d, ssid(%u)[%s:%d]",
							session->mailSize, session->analySize + (int)reqBufLen, hdr->sessionid, __func__, __LINE__);
						//SCLogInfo("close fp(%p)[%s:%d]", session->fp, __func__, __LINE__);
						fclose(session->fp);
						session->fp = NULL;
						continue;
					}

					data = (char *)SCMalloc(reqBufLen);
					if (NULL == data)
					{
						SCLogError("SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)reqBufLen, __func__, __LINE__);
						return PARSER_ERROR;
					}

					ret = evbuffer_remove(session->reqBuf, data, reqBufLen);
					if (-1 == ret)
					{
						SCLogError("remove data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						SCFree(data);
						data = NULL;
						return PARSER_ERROR;
					}

					session->analySize += (int)reqBufLen;
					//SCLogError("===========analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);

					if (PARSER_OK != mail_writeDataToFile(session, MAIL_SMTP, data, (int)reqBufLen))
					{
						SCLogError("write data to file failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						SCFree(data);
						data = NULL;
						return PARSER_ERROR;
					}

					SCFree(data);
					data = NULL;
				}
				else
				{
					/* Find, write data and close fp */
					offset = (int)(pos.pos) + MAIL_TWO_WRAP_LEN;
					data = (char *)SCMalloc(offset);
					if (NULL == data)
					{
						SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset, __func__, __LINE__);
						return PARSER_ERROR;
					}

					ret = evbuffer_remove(session->reqBuf, data, pos.pos + MAIL_TWO_WRAP_LEN);
					if (-1 == ret)
					{
						SCLogError("remove data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						SCFree(data);
						data = NULL;
						return PARSER_ERROR;
					}

					session->analySize += offset;
					//SCLogError("===========analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);

					if (PARSER_OK != mail_writeDataToFile(session, MAIL_SMTP, data, (int)(pos.pos)))
					{
						SCLogError("write data to file failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						SCFree(data);
						data = NULL;
						return PARSER_ERROR;
					}

					SCFree(data);
					data = NULL;
					//SCLogInfo("close fp(%p)[%s:%d]", session->fp, __func__, __LINE__);
					fclose(session->fp);
					session->fp = NULL;
				}
			}
			else
			{
				/* Check data all receive */
				pos = evbuffer_search(session->reqBuf, "\r\n\r\n", MAIL_TWO_WRAP_LEN, NULL);
				if (-1 == pos.pos)
				{
					/* Not find */

					if (MAIL_SMTP_END_LEN > reqBufLen)
					{
						break;
					}

					ret = evbuffer_copyout(session->reqBuf, tmp, MAIL_SMTP_END_LEN);
					if (-1 == ret)
					{
						SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						return PARSER_ERROR;
					}

					/* check end flag */
					if (!strncmp(tmp, ".\r\n", MAIL_SMTP_END_LEN))
					{
						//SCLogInfo("analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);
						session->isStartMail = PARSER_BFALSE;
						evbuffer_drain(session->reqBuf, MAIL_SMTP_END_LEN);
					}
					else
					{
						break;
					}
				}
				else
				{
					/* Find */
					offset = (int)(pos.pos) + MAIL_TWO_WRAP_LEN;
					data = (char *)SCMalloc(offset + 1);
					if (NULL == data)
					{
						SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset + 1, __func__, __LINE__);
						return PARSER_ERROR;
					}

					data[offset] = '\0';
					ret = evbuffer_remove(session->reqBuf, data, pos.pos + MAIL_TWO_WRAP_LEN);
					if (-1 == ret)
					{
						SCLogError("remove data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						SCFree(data);
						data = NULL;
						return PARSER_ERROR;
					}

					session->analySize += offset;
					//SCLogInfo("analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);

					/* Check mail body */
					if (PARSER_OK != smtp_checkMailBodySeg(hdr, session, data, offset))
					{
						SCFree(data);
						data = NULL;
						return PARSER_ERROR;
					}

					SCFree(data);
					data = NULL;
				}
			}
		}
		else
		{
			/* Not start mail */

			/* Check data all receive */
			pos = evbuffer_search(session->reqBuf, "\r\n", MAIL_ONE_WRAP_LEN, NULL);
			if (-1 == pos.pos)
			{
				/* Not find */
				break;
			}
			else
			{
				/* Find */
				offset = (int)(pos.pos) + MAIL_ONE_WRAP_LEN;
				data = (char *)SCMalloc(offset + 1);
				if (NULL == data)
				{
					SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset + 1, __func__, __LINE__);
					return PARSER_ERROR;
				}

				data[offset] = '\0';
				ret = evbuffer_remove(session->reqBuf, data, pos.pos + MAIL_ONE_WRAP_LEN);
				if (-1 == ret)
				{
					SCLogError("remove data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
					SCFree(data);
					data = NULL;
					return PARSER_ERROR;
				}

				/* Check mail header */
				if (PARSER_OK != smtp_getMailHeaderSeg(hdr, session, data, offset))
				{
					SCFree(data);
					data = NULL;
					return PARSER_ERROR;
				}

				SCFree(data);
				data = NULL;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : smtp_checkCltReqbufData
*Action      : check the full session in buff
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int smtp_checkCltReqbufData(struct filter_header *hdr, MAIL_SESSION *session, char *buff, int len)
{
	int offset;
	char *pos = NULL;
	char *data = NULL;

	while (1)
	{
		/* Check data length of request buff */
		if (0 >= len)
		{
			break;
		}

		if (session->isStartMail)
		{
			/* Start mail already */
			if (session->fp)
			{
				/* Check data all receive */
				pos = strnstr(buff, "\r\n\r\n", len);
				if (NULL == pos)
				{
					/* Not find, write data to fp */

					if (session->mailSize < (session->analySize + len))
					{
						SCLogError("mail content analy failed, mail size:%d, analy size:%d, ssid(%u)[%s:%d]",
							session->mailSize, session->analySize + len, hdr->sessionid, __func__, __LINE__);
						//SCLogInfo("close fp(%p)[%s:%d]", session->fp, __func__, __LINE__);
						fclose(session->fp);
						session->fp = NULL;
						continue;
					}

					session->analySize += len;
					//SCLogError("===========analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);

					if (PARSER_OK != mail_writeDataToFile(session, MAIL_SMTP, buff, len))
					{
						SCLogError("write data to file failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						return PARSER_ERROR;
					}
					break;
				}
				else
				{
					/* Find, write data and close fp */
					offset = (int)(pos - buff);

					session->analySize += offset;
					session->analySize += 4;
					//SCLogError("===========analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);

					if (PARSER_OK != mail_writeDataToFile(session, MAIL_SMTP, buff, offset))
					{
						SCLogError("write data to file failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
						return PARSER_ERROR;
					}

					//SCLogInfo("close fp(%p)[%s:%d]", session->fp, __func__, __LINE__);
					fclose(session->fp);
					session->fp = NULL;

					offset += 4;
					buff += offset;
					len -= offset;
				}
			}
			else
			{
				pos = strnstr(buff, "\r\n\r\n", len);
				if (NULL == pos)
				{
					/* Not find, add to event buffer */

					/* check end flag */
					if (!strncmp(buff, ".\r\n", MAIL_SMTP_END_LEN))
					{
						//SCLogInfo("analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);
						session->isStartMail = PARSER_BFALSE;
						if (MAIL_SMTP_END_LEN < len)
						{
							buff += MAIL_SMTP_END_LEN;
							len -= MAIL_SMTP_END_LEN;
						}
					}
					else
					{
						if (0 != evbuffer_add(session->reqBuf, buff, len))
						{
							SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
							return PARSER_ERROR;
						}
						break;
					}
				}
				else
				{
					/* Find */

					/* Check mail body */
					offset = (int)(pos - buff) + MAIL_TWO_WRAP_LEN;
					data = (char *)SCMalloc(offset + 1);
					if (NULL == data)
					{
						SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset + 1, __func__, __LINE__);
						return PARSER_ERROR;
					}

					data[offset] = '\0';
					memcpy(data, buff, offset);

					session->analySize += offset;
					//SCLogInfo("analy size:%d, ssid(%u)[%s:%d]", session->analySize, hdr->sessionid, __func__, __LINE__);

					if (PARSER_OK != smtp_checkMailBodySeg(hdr, session, data, offset))
					{
						SCFree(data);
						data = NULL;
						return PARSER_ERROR;
					}

					SCFree(data);
					data = NULL;
					buff += offset;
					len -= offset;
				}
			}
		}
		else
		{
			/* Not start mail */

			/* Check data all receive */
			pos = strnstr(buff, "\r\n", len);
			if (NULL == pos)
			{
				/* Not find, add to event buffer */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
					return PARSER_ERROR;
				}
				break;
			}
			else
			{
				/* Find */

				/* Check mail header */
				offset = (int)(pos - buff) + MAIL_ONE_WRAP_LEN;
				data = (char *)SCMalloc(offset + 1);
				if (NULL == data)
				{
					SCLogError("SCMalloc memory failed, size(%d)[%s:%d]", offset + 1, __func__, __LINE__);
					return PARSER_ERROR;
				}

				data[offset] = '\0';
				memcpy(data, buff, offset);
				if (PARSER_OK != smtp_getMailHeaderSeg(hdr, session, buff, offset))
				{
					SCFree(data);
					data = NULL;
					return PARSER_ERROR;
				}

				SCFree(data);
				data = NULL;
				buff += offset;
				len -= offset;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : smtp_handleClientReq
*Action      : handle client request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int smtp_handleClientReq(struct filter_header *hdr, MAIL_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Send request eventbuffer */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("add data to session req buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		if (PARSER_OK != smtp_checkCltEventReqbufData(hdr, session))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send request buffer */
		if ((NULL != buff) && (0 < len))
		{
			if (PARSER_OK != smtp_checkCltReqbufData(hdr, session, (char *)buff, (int)len))
			{
				return PARSER_ERROR;
			}
		}
	}

	/* Send data */
	if ((NULL != buff) && (0 < len))
	{
		if (0 != buffer_sendtofwd(hdr, buff, len))
		{
			SCLogError("send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server request message")
/************************************************************
*Function    : smtp_handleServerReq
*Action      : handle server request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int smtp_handleServerReq(struct filter_header *hdr, MAIL_SESSION *session, const void *buff, size_t len)
{
	return smtp_handleClientReq(hdr, session, buff, len);
}
#endif

/************************************************************
*Function    : smtp_checkFwdObjData
*Action      : check form forward obj data
*Input       : hdr          packet processing header information
			   obj          data obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.3
*Instruction : null
************************************************************/
static int smtp_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
{
	if (obj->cmd != FWDCMD_FORWARDDATA)
	{
		SCLogError("not fwd event type, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (0 == obj->has_buffdata)
	{
		SCLogError("obj data is null, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

#if GAP_DESC("client response message")
/************************************************************
*Function    : smtp_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int smtp_handleClientRsp(struct filter_header *hdr, MAIL_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		/* Send response eventbuffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("add data to session rsp buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
		{
			SCLogError("send session buffer data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send response buffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server response message")
/************************************************************
*Function    : smtp_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int smtp_handleServerRsp(struct filter_header *hdr, MAIL_SESSION *session, ForwardObject *obj)
{
	return smtp_handleClientRsp(hdr, session, obj);
}
#endif

/************************************************************
*Function    : smtp_data
*Action      : smtp protocol data processing
*Input       : hdr  packet processing header information
			   ev   data packet processing type
			   buff data
			   len  data len
*Output      : null
*Return      : FLTRET_CLOSE     close session
			   FLTRET_OK        normal processing
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static enum FLT_RET smtp_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	MAIL_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("invalid para, hdr(%p)[%s:%d]", hdr, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = smtp_allocSession();
		if (session == NULL)
		{
			SCLogError("create new session failed, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		session->connecting = MAIL_CONNECTING;
		SCLogInfo("connect in, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		break;
	}

	case FLTEV_ONSVROK:         /* Connect to server success or failure */
	{
		int isok;

		if (NULL == hdr->user)
		{
			SCLogError("invalid para, hdr(%p), user(%p)[%s:%d]", hdr, hdr->user, __func__, __LINE__);
			return smtp_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(int) != (unsigned int)len))
		{
			SCLogError("invalid para, buff(%p), len(%u)[%s:%d]", buff, (unsigned int)len, __func__, __LINE__);
			return smtp_closeSession(hdr, (int)len, "Invalid socket len");
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			SCLogError("connect server failed, sock(%d), ssid(%u)[%s:%d]", isok, hdr->sessionid, __func__, __LINE__);
			return smtp_closeSession(hdr, (int)len, "Invalid socket fd");
		}

		SCLogInfo("connect server success, sock(%d), ssid(%u)[%s:%d]", isok, hdr->sessionid, __func__, __LINE__);

		session = hdr->user;
		session->connecting = MAIL_CONNECTED;
		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return smtp_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}

		break;
	}

	case FLTEV_ONSOCKDATA:      /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("invalid para, hdr(%p), user(%p)[%s:%d]", hdr, hdr->user, __func__, __LINE__);
			return smtp_closeSession(hdr, (int)len, "User data is NULL");
		}

		session = hdr->user;

		SCLogInfo("on socket data, len(%u), sessionid(%u)[%s:%d]", (unsigned int)len, hdr->sessionid, __func__, __LINE__);

		if (MAIL_DISCONNECT == session->connecting)
		{
			/* Has not handshake, receive data, not handle */
			SCLogWarning("svr not connect, not progress.... ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return FLTRET_OK;
		}

		if (MAIL_CONNECTING == session->connecting)
		{
			if ((NULL != buff) && (0 < len))
			{
				/* Connecting, receive data, add to req buffer, when connected and brush out */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("add data to session buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
					return smtp_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("svr not ready, delay.... ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			}
			return FLTRET_OK;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != smtp_handleClientReq(hdr, session, buff, len))
			{
				return smtp_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (PARSER_OK != smtp_handleServerReq(hdr, session, buff, len))
			{
				return smtp_closeSession(hdr, (int)len, "Handle server request data");
			}
		}

		break;
	}

	case FLTEV_ONFWDDATA:       /* Receive data from arbitration-machine */
	{
		ForwardObject *obj = NULL;

		if (NULL == hdr->user)
		{
			SCLogError("invalid para, hdr(%p), user(%p)[%s:%d]", hdr, hdr->user, __func__, __LINE__);
			return smtp_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("invalid para, buff(%p), len(%u)[%s:%d]", buff, (unsigned int)len, __func__, __LINE__);
			return smtp_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		SCLogInfo("receive data from fwd, len(%u), sessionid(%u)[%s:%d]",
			(unsigned int)obj->buffdata.len, hdr->sessionid, __func__, __LINE__);

		if (PARSER_OK != smtp_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != smtp_handleClientRsp(hdr, session, obj))
			{
				return smtp_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != smtp_handleServerRsp(hdr, session, obj))
			{
				return smtp_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return smtp_closeSession(hdr, 0, NULL);
		break;
	}

	default:                    /* Not handle, return ok */
	{
		break;
	}
	}

	return FLTRET_OK;
}

/************************************************************
*Function    : smtp_free
*Action      : smtp free
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int smtp_free(void)
{
	g_smtpConfig.dataRule = MAIL_DATA_DROP;
	g_smtpConfig.isSaveAttachment = PARSER_BFALSE;
	return FLTRET_OK;
}

/************************************************************
*Function    : smtp_init
*Action      : smtp init
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int smtp_init(void)
{
	char command[MAIL_ATTACHMENT_PATH_LEN];

	snprintf(command, MAIL_ATTACHMENT_PATH_LEN, "mkdir -p %s", MAIL_ATTACHMENT_PATH);
	(void)cmd_system_novty(command);
	g_smtpConfig.dataRule = MAIL_DATA_DROP;
	g_smtpConfig.isSaveAttachment = PARSER_BFALSE;
	return FLTRET_OK;
}

/************************************************************
*Function    : smtp_checkData
*Action      : smtp check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID smtp_checkData(const void *buff, size_t len)
{
	if ((4 < len) && !memcmp(buff, "220 ", 4))
	{
		return SVR_ID_SMTP;
	}
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_smtp
*Action      : smtp protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static struct packet_filter g_filter_smtp =
{
	SVR_ID_SMTP,
	"smtp parser",
	smtp_init,
	smtp_data,
	smtp_free,
	smtp_checkData
};

PROTOCOL_FILTER_OP(smtp)

