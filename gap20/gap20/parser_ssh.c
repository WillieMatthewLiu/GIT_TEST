/********************************************************************************

		   Copyright (C), 2016, 2016, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_ssh.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2016.12.27
Description    : SSH protocol process
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#include <iconv.h>
#include "app_common.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gap_stgy.h"
#include "gapconfig.h"
#include "parser_tcp.h"
#include "db_mysql.h"
#include "parser_common.h"

/* Description */
#define SSH_DESC(X)                 1

/* BOOL definition */
#define SSH_BTRUE                   ~0
#define SSH_BFALSE                  0

/* Return Value definition */
#define SSH_RETURN_OK               0
#define SSH_RETURN_ERROR            (-1)

/* Characteristic length */
#define SSH_DATA_SIGN_LEN           3

/* IP cache size */
#define SSH_IP_BUFF_SIZE            64

/* Session connection status */
typedef enum SSH_CONNECT_STATUS_E
{
	SSH_DISCONNECT = 0,
	SSH_CONNECTING,
	SSH_CONNECTED
} SSH_CONNECT_STATUS;

/* Data state */
typedef enum SSH_DATA_STATUS_E
{
	SSH_DATA_INIT = 0,
	SSH_DATA_REQ_PREPARE,
	SSH_DATA_RSP_PREPARE,
	SSH_DATA_NORMAL,
	SSH_DATA_ABNORMAL
} SSH_DATA_STATUS;

/* Session information */
typedef struct SSH_SESSION_S
{
	int connecting;
	int dataStatus;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} SSH_SESSION;

/* Feature information */
static unsigned char g_sshDataSign[SSH_DATA_SIGN_LEN] = { 0x53, 0x53, 0x48 };

/************************************************************
*Function    : ssh_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static SSH_SESSION *ssh_allocSession(void)
{
	SSH_SESSION *session = NULL;

	session = SCMalloc(sizeof(SSH_SESSION));
	if (NULL == session)
	{
		SCLogError("SSH[ERROR]: SCMalloc memory failed, size(%u)", (unsigned int)sizeof(SSH_SESSION));
		return NULL;
	}
	memset(session, 0, sizeof(*session));
	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("SSH[ERROR]: evbuffer_new failed");
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("SSH[ERROR]: evbuffer_new failed");
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->connecting = SSH_DISCONNECT;
	session->dataStatus = SSH_DATA_INIT;
	return session;
}

/************************************************************
*Function    : ssh_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void ssh_freeSession(SSH_SESSION *session)
{
	evbuffer_free(session->rspBuf);
	session->rspBuf = NULL;
	evbuffer_free(session->reqBuf);
	session->reqBuf = NULL;
	session->dataStatus = SSH_DATA_INIT;
	session->connecting = SSH_DISCONNECT;
	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : ssh_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void ssh_writeSeceventLog(struct filter_header *hdr, int packLen, char *content)
{
	char sip[SSH_IP_BUFF_SIZE];
	char dip[SSH_IP_BUFF_SIZE];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	proto = (char*)server_strfromid(SVR_ID_SSH);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
		aclData->user, "none", l_critical, aclData->groupname, "false", packLen, content);
}

/************************************************************
*Function    : ssh_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET ssh_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	SSH_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogWarning("SSH[WARN]: invalid para, hdr(%p), user(%p), maybe session is closed", hdr, hdr->user);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		ssh_writeSeceventLog(hdr, packLen, content);
	}

	session = hdr->user;

	SCLogInfo("SSH[INFO]: on socket close, ssid(%u)", hdr->sessionid);

	ssh_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

/************************************************************
*Function    : ssh_strnstr
*Action      : Find src in the first len character of dst
*Input       : dst  dest string
			   src  source string
			   len  source len
*Output      : null
*Return      : dst      find
			   NULL     not find
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static char *ssh_strnstr(char *dst, char *src, int len)
{
	int dstLen;
	int srcLen;

	if ((NULL == dst) || (NULL == src))
	{
		return NULL;
	}

	srcLen = strlen(src);
	if (0 == srcLen)
	{
		return (char *)dst;
	}

	dstLen = strlen(dst);
	len = (len > dstLen) ? dstLen : len;
	while (len >= srcLen)
	{
		len--;
		if (!memcmp(dst, src, srcLen))
		{
			return (char *)dst;
		}
		dst++;
	}

	return NULL;
}

/************************************************************
*Function    : ssh_sendEnvClientReq
*Action      : Send event buffer request data
*Input       : hdr      packet processing header information
			   reqBuf   request buffer
*Output      : null
*Return      : SSH_RETURN_OK    success
			   SSH_RETURN_ERROR false
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static int ssh_sendEnvClientReq(struct filter_header *hdr, struct evbuffer *reqBuf)
{
	struct evbuffer_ptr pos;

	pos = evbuffer_search(reqBuf, "\r\n", 2, NULL);
	if (-1 == pos.pos)
	{
		SCLogError("SSH[ERROR]: not find end symbol, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	if (-1 == evbuffer_sendtofwd(hdr, reqBuf, pos.pos + 2))
	{
		SCLogError("SSH[ERROR]: send session buffer data to forward failed, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	return SSH_RETURN_OK;
}

/************************************************************
*Function    : ssh_sendBufClientReq
*Action      : Send buffer request data
*Input       : hdr      packet processing header information
			   reqBuf   request buffer
			   buff     buffer
			   len      buffer len
*Output      : null
*Return      : SSH_RETURN_OK    success
			   SSH_RETURN_ERROR false
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static int ssh_sendBufClientReq(struct filter_header *hdr, struct evbuffer *reqBuf, char *buff, int len)
{
	int sendLen;
	char *pos = NULL;

	pos = ssh_strnstr(buff, "\r\n", len);
	if (NULL == pos)
	{
		SCLogError("SSH[ERROR]: not find end symbol, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	sendLen = pos - buff + 2;
	if (0 != buffer_sendtofwd(hdr, buff, (size_t)sendLen))
	{
		SCLogError("SSH[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	if (len > sendLen)
	{
		if (0 != evbuffer_add(reqBuf, pos + 2, (size_t)(len - sendLen)))
		{
			SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
			return SSH_RETURN_ERROR;
		}
	}

	return SSH_RETURN_OK;
}

/************************************************************
*Function    : ssh_sendEnvClientRsp
*Action      : Send event buffer response data
*Input       : hdr      packet processing header information
			   rspBuf   response buffer
*Output      : null
*Return      : SSH_RETURN_OK    success
			   SSH_RETURN_ERROR false
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static int ssh_sendEnvClientRsp(struct filter_header *hdr, struct evbuffer *rspBuf)
{
	struct evbuffer_ptr pos;

	pos = evbuffer_search(rspBuf, "\r\n", 2, NULL);
	if (-1 == pos.pos)
	{
		SCLogError("SSH[ERROR]: not find end symbol, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	if (-1 == evbuffer_sendtoreq(hdr, rspBuf, pos.pos + 2))
	{
		SCLogError("SSH[ERROR]: send session buffer data to forward failed, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	return SSH_RETURN_OK;
}

/************************************************************
*Function    : ssh_sendBufClientRsp
*Action      : Send buffer response data
*Input       : hdr      packet processing header information
			   rspBuf   response buffer
			   buff     buffer
			   len      buffer len
*Output      : null
*Return      : SSH_RETURN_OK    success
			   SSH_RETURN_ERROR false
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static int ssh_sendBufClientRsp(struct filter_header *hdr, struct evbuffer *rspBuf, char *buff, int len)
{
	int sendLen;
	char *pos = NULL;

	pos = ssh_strnstr(buff, "\r\n", len);
	if (NULL == pos)
	{
		SCLogError("SSH[ERROR]: not find end symbol, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	sendLen = pos - buff + 2;
	if (0 != buffer_sendtoreq(hdr, buff, (size_t)sendLen))
	{
		SCLogError("SSH[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
		return SSH_RETURN_ERROR;
	}

	if (len > sendLen)
	{
		if (0 != evbuffer_add(rspBuf, pos + 2, (size_t)(len - sendLen)))
		{
			SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
			return SSH_RETURN_ERROR;
		}
	}

	return SSH_RETURN_OK;
}

/************************************************************
*Function    : ssh_isHeaderFull
*Action      : check head data is complete
*Input       : eventBuf     event buffer
*Output      : null
*Return      : SSH_BFALSE   not full
			   SSH_BTRUE    full
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static char ssh_isHeaderFull(struct evbuffer *eventBuf)
{
	struct evbuffer_ptr pos;

	pos = evbuffer_search(eventBuf, "\r\n", 2, NULL);
	if (-1 == pos.pos)
	{
		return SSH_BFALSE;
	}
	else
	{
		return SSH_BTRUE;
	}
}

/************************************************************
*Function    : ssh_data
*Action      : SSH protocol data processing
*Input       : hdr  packet processing header information
			   ev   data packet processing type
			   buff data
			   len  data len
*Output      : null
*Return      : FLTRET_CLOSE     close session
			   FLTRET_OK        normal processing
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static enum FLT_RET ssh_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SSH_SESSION *session = NULL;

	if (ev == FLTEV_ONCLIIN)
	{
		/* To connect server */
		if (NULL == hdr)
		{
			SCLogError("SSH[ERROR]: invalid para, hdr(%p)", hdr);
			return FLTRET_CLOSE;
		}

		session = ssh_allocSession();
		if (session == NULL)
		{
			SCLogError("SSH[ERROR]: create new opc session failed, ssid(%u)", hdr->sessionid);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		session->connecting = SSH_CONNECTING;
		SCLogInfo("SSH[INFO]: connect in, ssid(%u)", hdr->sessionid);
	}
	else if (ev == FLTEV_ONSVROK)
	{
		/* Connect to server success or failure */

		int isok;

		if ((NULL == hdr) || (NULL == hdr->user))
		{
			SCLogWarning("SSH[WARN]: invalid para, maybe session is closed, hdr(%p), user(%p)", hdr, hdr->user);
			return FLTRET_OK;
		}

		if ((NULL == buff) || ((unsigned int)sizeof(isok) != (unsigned int)len))
		{
			SCLogError("SSH[ERROR]: invalid para, buff(%p), len(%u)", buff, (unsigned int)len);
			return FLTRET_OK;
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			SCLogError("SSH[ERROR]: connect server failed, sock(%d), ssid(%u)", isok, hdr->sessionid);
			return ssh_closeSession(hdr, (int)len, "Check isock");
		}

		SCLogInfo("SSH[INFO]: connect server success, sock(%d), ssid(%u)", isok, hdr->sessionid);

		session = hdr->user;
		session->connecting = SSH_CONNECTED;
		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return ssh_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}
	}
	else if (ev == FLTEV_ONSOCKDATA)
	{
		/* Receive client or server data */

		unsigned char reqDataBuf[SSH_DATA_SIGN_LEN];

		if ((NULL == hdr) || (NULL == hdr->user))
		{
			SCLogError("SSH[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return FLTRET_OK;
		}

		session = hdr->user;

		SCLogInfo("SSH[INFO]: on socket data, len(%d), ssid(%u)", (int)len, hdr->sessionid);

		if (SSH_DISCONNECT == session->connecting)
		{
			/* Has not handshake, receive data, not handle */
			SCLogWarning("SSH[WARN]: svr not connect, not progress.... ssid(%u)", hdr->sessionid);
			return FLTRET_OK;
		}
		else if (SSH_CONNECTING == session->connecting)
		{
			if ((NULL != buff) && (0 < len))
			{
				/* Connecting, receive data, add to req buffer, when connected and brush out */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
					return ssh_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("SSH[INFO]: svr not ready, delay.... ssid(%u)", hdr->sessionid);
			}
			else
			{
				/* Data abnormal, not handle */
				SCLogWarning("SSH[WARN]: invalid buffer, buffer(%p), len(%u), ssid(%u)",
					buff, (unsigned int)len, hdr->sessionid);
			}
			return FLTRET_OK;
		}
		else if (SSH_CONNECTED == session->connecting)
		{
			if (NULL != hdr->svr)
			{
				if (0 < evbuffer_get_length(session->reqBuf))
				{
					SCLogInfo("SSH[INFO]: add to reqbuf, len(%u), ssid(%u)", (unsigned int)len, hdr->sessionid);

					if ((NULL != buff) && (0 < len))
					{
						if (0 != evbuffer_add(session->reqBuf, buff, len))
						{
							SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
							return ssh_closeSession(hdr, (int)len, "Add data to request eventbuffer");
						}
					}

					if (SSH_DATA_NORMAL != session->dataStatus)
					{
						if ((SSH_DATA_INIT == session->dataStatus) || (SSH_DATA_RSP_PREPARE == session->dataStatus))
						{
							if (!ssh_isHeaderFull(session->reqBuf))
							{
								/* Head not full, return ok */
								return FLTRET_OK;
							}

							if (-1 == evbuffer_copyout(session->reqBuf, (void *)reqDataBuf, SSH_DATA_SIGN_LEN))
							{
								SCLogError("SSH[ERROR]: copy data from req buff failed, ssid(%u)", hdr->sessionid);
								return ssh_closeSession(hdr, (int)len, "Copy data from request eventbuffer");
							}

							if (0 == strncmp((void *)reqDataBuf, (void *)g_sshDataSign, SSH_DATA_SIGN_LEN))
							{
								if (SSH_DATA_INIT == session->dataStatus)
								{
									session->dataStatus = SSH_DATA_REQ_PREPARE;
								}
								else
								{
									session->dataStatus = SSH_DATA_NORMAL;
								}

								if (SSH_RETURN_OK != ssh_sendEnvClientReq(hdr, session->reqBuf))
								{
									return ssh_closeSession(hdr, (int)len, "Send request eventbuffer");
								}
							}
							else
							{
								session->dataStatus = SSH_DATA_ABNORMAL;
								SCLogError("SSH[ERROR]: invalid ssh session data format, ssid(%u)", hdr->sessionid);
								return ssh_closeSession(hdr, (int)len, "Check request data format");
							}
						}
						/* else Not handle */
					}

					if (SSH_DATA_NORMAL == session->dataStatus)
					{
						if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
						{
							SCLogError("SSH[ERROR]: send session buffer data to forward failed, ssid(%u)", hdr->sessionid);
							return ssh_closeSession(hdr, (int)len, "Send request eventbuffer");
						}
					}
				}
				else if ((NULL != buff) && (0 < len))
				{
					/* Send buffer */
					SCLogInfo("SSH[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)len, hdr->sessionid);

					if (SSH_DATA_NORMAL == session->dataStatus)
					{
						if (0 != buffer_sendtofwd(hdr, buff, len))
						{
							SCLogError("SSH[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
							return ssh_closeSession(hdr, (int)len, "Send request buffer");
						}
					}
					else
					{
						if ((SSH_DATA_INIT == session->dataStatus) || (SSH_DATA_RSP_PREPARE == session->dataStatus))
						{
							if (NULL == ssh_strnstr((char *)buff, "\r\n", len))
							{
								/* Head not full, add to reqbuf, return ok */
								if (0 != evbuffer_add(session->reqBuf, buff, len))
								{
									SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
									return ssh_closeSession(hdr, (int)len, "Add data to request eventbuffer");
								}
								return FLTRET_OK;
							}

							if (0 == strncmp((void *)buff, (void *)g_sshDataSign, SSH_DATA_SIGN_LEN))
							{
								if (SSH_DATA_INIT == session->dataStatus)
								{
									session->dataStatus = SSH_DATA_REQ_PREPARE;
									if (SSH_RETURN_OK != ssh_sendBufClientReq(hdr, session->reqBuf, (char *)buff, len))
									{
										return ssh_closeSession(hdr, (int)len, "Send request buffer");
									}
								}
								else
								{
									session->dataStatus = SSH_DATA_NORMAL;
									if (0 != buffer_sendtofwd(hdr, buff, len))
									{
										SCLogError("SSH[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
										return ssh_closeSession(hdr, (int)len, "Send request buffer");
									}
								}
							}
							else
							{
								session->dataStatus = SSH_DATA_ABNORMAL;
								SCLogError("SSH[ERROR]: invalid ssh session data format, ssid(%u)", hdr->sessionid);
								return ssh_closeSession(hdr, (int)len, "Check request data format");
							}
						}
						else
						{
							if (0 != evbuffer_add(session->reqBuf, buff, len))
							{
								SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
								return ssh_closeSession(hdr, (int)len, "Add data to request eventbuffer");
							}
						}
					}
				}
			}
			else
			{
				if (0 < evbuffer_get_length(session->reqBuf))
				{
					SCLogInfo("SSH[INFO]: send to fwd, len(%u), ssid(%u)",
						(unsigned int)evbuffer_get_length(session->reqBuf), hdr->sessionid);

					if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
					{
						SCLogError("SSH[ERROR]: send session buffer data to forward failed, ssid(%u)",
							hdr->sessionid);
						return ssh_closeSession(hdr, (int)len, "Send request eventbuffer");
					}
				}

				if ((NULL != buff) && (0 < len))
				{
					/* Send this data */
					SCLogInfo("SSH[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)len, hdr->sessionid);

					if (0 != buffer_sendtofwd(hdr, buff, len))
					{
						SCLogError("SSH[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
						return ssh_closeSession(hdr, (int)len, "Send request buffer");
					}
				}
			}
		}
		else
		{
			/* Unknown state: not handle */
			SCLogWarning("SSH[WARN]: invalid connetcion status(%d), ssid(%u)",
				session->connecting, hdr->sessionid);
		}
	}
	else if (ev == FLTEV_ONFWDDATA)
	{
		/* Receive data from arbitration-machine */

		ForwardObject *obj = NULL;
		unsigned char rspDataBuf[SSH_DATA_SIGN_LEN];

		if ((NULL == hdr) || (NULL == hdr->user))
		{
			SCLogError("SSH[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return FLTRET_OK;
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("SSH[ERROR]: invalid para, buff(%p), len(%u)", buff, (unsigned int)len);
			return FLTRET_OK;
		}

		session = hdr->user;
		obj = (ForwardObject *)buff;

		SCLogInfo("SSH[INFO]: receive data from fwd, len(%u), sessionid(%u)",
			(unsigned int)obj->buffdata.len, hdr->sessionid);

		if (NULL != hdr->svr)
		{
			if (obj->cmd == FWDCMD_FORWARDDATA)
			{
				if (0 < evbuffer_get_length(session->rspBuf))
				{
					if ((obj->has_buffdata) && (NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
					{
						SCLogInfo("SSH[INFO]: add to reqbuf, len(%u), ssid(%u)",
							(unsigned int)obj->buffdata.len, hdr->sessionid);

						if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
						{
							SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
							return ssh_closeSession(hdr, (int)len, "Add data to response eventbuffer");
						}
					}

					if (SSH_DATA_NORMAL != session->dataStatus)
					{
						if ((SSH_DATA_INIT == session->dataStatus) || (SSH_DATA_REQ_PREPARE == session->dataStatus))
						{
							if (!ssh_isHeaderFull(session->rspBuf))
							{
								/* Head not full, return ok */
								return FLTRET_OK;
							}

							if (-1 == evbuffer_copyout(session->rspBuf, (void *)rspDataBuf, SSH_DATA_SIGN_LEN))
							{
								SCLogError("SSH[ERROR]: copy data from rsp buff failed, ssid(%u)", hdr->sessionid);
								return ssh_closeSession(hdr, (int)len, "Copy data from rsponse eventbuffer");
							}

							if (0 == strncmp((void *)rspDataBuf, (void *)g_sshDataSign, SSH_DATA_SIGN_LEN))
							{
								if (SSH_DATA_INIT == session->dataStatus)
								{
									session->dataStatus = SSH_DATA_RSP_PREPARE;
								}
								else
								{
									session->dataStatus = SSH_DATA_NORMAL;
								}

								if (SSH_RETURN_OK != ssh_sendEnvClientRsp(hdr, session->rspBuf))
								{
									return ssh_closeSession(hdr, (int)len, "Send response eventbuffer");
								}
							}
							else
							{
								session->dataStatus = SSH_DATA_ABNORMAL;
								SCLogError("SSH[ERROR]: invalid ssh session data format, ssid(%u)", hdr->sessionid);
								return ssh_closeSession(hdr, (int)len, "Check response data format");
							}
						}
						/* else Not handle */
					}

					if (SSH_DATA_NORMAL == session->dataStatus)
					{
						if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
						{
							SCLogError("SSH[ERROR]: send session buffer data to req failed, ssid(%u)", hdr->sessionid);
							return ssh_closeSession(hdr, (int)len, "Send response eventbuffer");
						}
					}
				}
				else if (obj->has_buffdata)
				{
					SCLogInfo("SSH[INFO]: on fwd data, len(%u), sessionid(%u)",
						(unsigned int)obj->buffdata.len, hdr->sessionid);

					if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
					{
						SCLogInfo("SSH[INFO]: sent to req, len(%u), sessionid(%u)",
							(unsigned int)obj->buffdata.len, hdr->sessionid);

						if (SSH_DATA_NORMAL == session->dataStatus)
						{
							if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
							{
								SCLogError("SSH[ERROR]: req callback failed, sessionid(%u)", hdr->sessionid);
								return ssh_closeSession(hdr, (int)len, "Send response buffer");
							}
						}
						else
						{
							if ((SSH_DATA_INIT == session->dataStatus) || (SSH_DATA_REQ_PREPARE == session->dataStatus))
							{
								if (NULL == ssh_strnstr((char *)obj->buffdata.data, "\r\n", (int)obj->buffdata.len))
								{
									/* Head not full, add to rspbuf, return ok */
									if (0 != evbuffer_add(session->rspBuf, buff, len))
									{
										SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
										return ssh_closeSession(hdr, (int)len, "Add data to response eventbuffer");
									}
									return FLTRET_OK;
								}

								if (0 == strncmp((void *)(obj->buffdata.data), (void *)g_sshDataSign, SSH_DATA_SIGN_LEN))
								{
									if (SSH_DATA_INIT == session->dataStatus)
									{
										session->dataStatus = SSH_DATA_RSP_PREPARE;
										if (SSH_RETURN_OK != ssh_sendBufClientRsp(hdr, session->rspBuf, (char *)(obj->buffdata.data), obj->buffdata.len))
										{
											return ssh_closeSession(hdr, (int)len, "Send response buffer");
										}
									}
									else
									{
										session->dataStatus = SSH_DATA_NORMAL;
										if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
										{
											SCLogError("SSH[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
											return ssh_closeSession(hdr, (int)len, "Send response buffer");
										}
									}
								}
								else
								{
									session->dataStatus = SSH_DATA_ABNORMAL;
									SCLogError("SSH[ERROR]: invalid ssh session data format, ssid(%u)", hdr->sessionid);
									return ssh_closeSession(hdr, (int)len, "Check response data format");
								}
							}
							else
							{
								if (0 != evbuffer_add(session->rspBuf, buff, len))
								{
									SCLogError("SSH[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
									return ssh_closeSession(hdr, (int)len, "Add data to response eventbuffer");
								}
							}
						}
					}
					else
					{
						SCLogWarning("SSH[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
					}
				}
				else
				{
					SCLogWarning("SSH[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
				}
			}
			else
			{
				SCLogWarning("SSH[WARN]: not fwd event type, sessionid(%u)", hdr->sessionid);
			}
		}
		else
		{
			if (obj->cmd == FWDCMD_FORWARDDATA)
			{
				if (obj->has_buffdata)
				{
					SCLogInfo("SSH[INFO]: on fwd data, len(%u), sessionid(%u)",
						(unsigned int)obj->buffdata.len, hdr->sessionid);

					if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
					{
						SCLogInfo("SSH[INFO]: sent to req, len(%u), sessionid(%u)",
							(unsigned int)obj->buffdata.len, hdr->sessionid);

						if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
						{
							SCLogError("SSH[ERROR]: req callback failed, sessionid(%u)", hdr->sessionid);
							return ssh_closeSession(hdr, (int)len, "Send response buffer");
						}
					}
					else
					{
						SCLogWarning("SSH[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
					}
				}
				else
				{
					SCLogWarning("SSH[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
				}
			}
			else
			{
				SCLogWarning("SSH[WARN]: not fwd event type, sessionid(%u)", hdr->sessionid);
			}
		}
	}
	else if (ev == FLTEV_ONSOCKERROR)
	{
		/* Close session */
		return ssh_closeSession(hdr, 0, NULL);
	}
	/* else Not handle, return ok */

	return FLTRET_OK;
}

/************************************************************
*Function    : ssh_free
*Action      : ssh free
*Input       : null
*Output      : null
*Return      : SSH_RETURN_OK         success
			   SSH_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static int ssh_free(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : ssh_init
*Action      : ssh init
*Input       : null
*Output      : null
*Return      : SSH_RETURN_OK         success
			   SSH_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static int ssh_init(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : ssh_checkData
*Action      : ssh check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID ssh_checkData(const void *buff, size_t len)
{
	if ((3 < len) && !memcmp(buff, "SSH", 3))
	{
		return SVR_ID_SSH;
	}
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_ssh
*Action      : ssh protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static struct packet_filter g_filter_ssh =
{
	SVR_ID_SSH,
	"ssh parser",
	ssh_init,
	ssh_data,
	ssh_free,
	ssh_checkData
};

PROTOCOL_FILTER_OP(ssh)

