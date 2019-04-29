/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_opc_ssdp.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.2.7
Description    : opcssdp protocol process
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
#include "gapconfig.h"
#include "gap_stgy.h"
#include "parser_tcp.h"
#include "db_mysql.h"
#include "parser_common.h"
#include "parser_opc.h"

/************************************************************
*Function    : opcssdp_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static OPCSSDP_SESSION *opcssdp_allocSession(void)
{
	OPCSSDP_SESSION *session = NULL;

	session = SCMalloc(sizeof(OPCSSDP_SESSION));
	if (NULL == session)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, (unsigned int)sizeof(OPCSSDP_SESSION));
		return NULL;
	}
	memset(session, 0, sizeof(*session));
	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("[%s:%d]evbuffer_new failed", __func__, __LINE__);
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("[%s:%d]evbuffer_new failed", __func__, __LINE__);
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->connecting = OPC_DISCONNECT;
	return session;
}

/************************************************************
*Function    : opcssdp_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opcssdp_freeSession(OPCSSDP_SESSION *session)
{
	evbuffer_free(session->rspBuf);
	session->rspBuf = NULL;
	evbuffer_free(session->reqBuf);
	session->reqBuf = NULL;
	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : opcssdp_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void opcssdp_writeSeceventLog(struct filter_header *hdr, int packLen, char *content)
{
	char sourceIp[OPC_IP_BUFF_LEN];
	char destIp[OPC_IP_BUFF_LEN];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;

	addr2str(hdr->ip->saddr, sourceIp);
	addr2str(hdr->ip->daddr, destIp);
	proto = (char*)server_strfromid(SVR_ID_OPCSSDP);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);

	INSERT_ACCESSAUDIT_LOG(autoId, sourceIp, destIp, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
		aclData->user, "none", l_critical, aclData->groupname, "false", packLen, content);
}

/************************************************************
*Function    : opcssdp_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET opcssdp_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	OPCSSDP_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogError("[%s:%d]invalid para, hdr(%p), user(%p), maybe session is closed", __func__, __LINE__, hdr, hdr->user);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		opcssdp_writeSeceventLog(hdr, packLen, content);
	}

	session = hdr->user;

	SCLogInfo("[%s:%d]on socket close, ssid(%u)", __func__, __LINE__, hdr->sessionid);

	opcssdp_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

#if GAP_DESC("client request message")
/************************************************************
*Function    : opcssdp_handleClientReq
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
static int opcssdp_handleClientReq(struct filter_header *hdr, OPCSSDP_SESSION *session, const void *buff, size_t len)
{
	/* Send request eventbuffer */
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	/* Send request buffer */
	if ((NULL != buff) && (0 < len))
	{
		if (0 != buffer_sendtofwd(hdr, buff, len))
		{
			SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server request message")
/************************************************************
*Function    : opcssdp_handleServerReq
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
static int opcssdp_handleServerReq(struct filter_header *hdr, OPCSSDP_SESSION *session, const void *buff, size_t len)
{
	/* Send request eventbuffer */
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		SCLogInfo("[%s:%d]send to fwd, len(%u), ssid(%u)",
			__func__, __LINE__, (unsigned int)evbuffer_get_length(session->reqBuf), hdr->sessionid);

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[%s:%d]send session buffer data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	/* Send request buffer */
	if ((NULL != buff) && (0 < len))
	{
		SCLogInfo("[%s:%d]send to fwd, len(%u), ssid(%u)", __func__, __LINE__, (unsigned int)len, hdr->sessionid);

		if (0 != buffer_sendtofwd(hdr, buff, len))
		{
			SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}
#endif

/************************************************************
*Function    : opcssdp_checkFwdObjData
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
static int opcssdp_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
{
	if (obj->cmd != FWDCMD_FORWARDDATA)
	{
		SCLogError("[%s:%d]not fwd event type, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}

	if (0 == obj->has_buffdata)
	{
		SCLogError("[%s:%d]obj data is null, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

#if GAP_DESC("client response message")
/************************************************************
*Function    : opcssdp_handleClientRsp
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
static int opcssdp_handleClientRsp(struct filter_header *hdr, OPCSSDP_SESSION *session, ForwardObject *obj)
{
	/* Send response eventbuffer */
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		SCLogInfo("[%s:%d]send to req, len(%u), ssid(%u)",
			__func__, __LINE__, (unsigned int)evbuffer_get_length(session->rspBuf), hdr->sessionid);

		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
		{
			SCLogError("[%s:%d]send session buffer data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	/* Send response buffer */
	if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
	{
		SCLogInfo("[%s:%d]send to req, len(%u), ssid(%u)", __func__, __LINE__, (unsigned int)(obj->buffdata.len), hdr->sessionid);

		if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
		{
			SCLogError("[%s:%d]send data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server response message")
/************************************************************
*Function    : opcssdp_handleClientRsp
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
static int opcssdp_handleServerRsp(struct filter_header *hdr, OPCSSDP_SESSION *session, ForwardObject *obj)
{
	/* Send response eventbuffer */
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		SCLogInfo("[%s:%d]send to req, len(%u), ssid(%u)",
			__func__, __LINE__, (unsigned int)evbuffer_get_length(session->rspBuf), hdr->sessionid);

		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
		{
			SCLogError("[%s:%d]send session buffer data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	/* Send response buffer */
	if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
	{
		SCLogInfo("[%s:%d]send to req, len(%u), ssid(%u)", __func__, __LINE__, (unsigned int)(obj->buffdata.len), hdr->sessionid);

		if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
		{
			SCLogError("[%s:%d]send data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}
#endif

/************************************************************
*Function    : opcssdp_data
*Action      : opcssdp protocol data processing
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
static enum FLT_RET opcssdp_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	OPCSSDP_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("[%s:%d]invalid para, hdr(%p)", __func__, __LINE__, hdr);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = opcssdp_allocSession();
		if (session == NULL)
		{
			SCLogError("[%s:%d]create new session failed, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		session->connecting = OPC_CONNECTING;
		SCLogInfo("[%s:%d]connect in, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		break;
	}

	case FLTEV_ONSVROK:         /* Connect to server success or failure */
	{
		int isok;

		if (NULL == hdr->user)
		{
			SCLogError("[%s:%d]invalid para, hdr(%p), user(%p)", __func__, __LINE__, hdr, hdr->user);
			return opcssdp_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(int) != (unsigned int)len))
		{
			SCLogError("[%s:%d]invalid para, buff(%p), len(%u)", __func__, __LINE__, buff, (unsigned int)len);
			return opcssdp_closeSession(hdr, (int)len, "Invalid socket len");
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			SCLogError("[%s:%d]connect server failed, sock(%d), ssid(%u)", __func__, __LINE__, isok, hdr->sessionid);
			return opcssdp_closeSession(hdr, (int)len, "Invalid socket fd");
		}

		SCLogInfo("[%s:%d]connect server success, sock(%d), ssid(%u)", __func__, __LINE__, isok, hdr->sessionid);

		session = hdr->user;
		session->connecting = OPC_CONNECTED;
		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return opcssdp_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}

		break;
	}

	case FLTEV_ONSOCKDATA:      /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[%s:%d]invalid para, hdr(%p), user(%p)", __func__, __LINE__, hdr, hdr->user);
			return opcssdp_closeSession(hdr, (int)len, "User data is NULL");
		}

		session = hdr->user;

		SCLogInfo("[%s:%d]on socket data, len(%u), sessionid(%u)", __func__, __LINE__, (unsigned int)len, hdr->sessionid);

		if (OPC_DISCONNECT == session->connecting)
		{
			/* Has not handshake, receive data, not handle */
			SCLogError("[%s:%d]svr not connect, not progress.... ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return FLTRET_OK;
		}

		if (OPC_CONNECTING == session->connecting)
		{
			if ((NULL != buff) && (0 < len))
			{
				/* Connecting, receive data, add to req buffer, when connected and brush out */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("[%s:%d]add data to session buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
					return opcssdp_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("[%s:%d]svr not ready, delay.... ssid(%u)", __func__, __LINE__, hdr->sessionid);
			}
			return FLTRET_OK;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != opcssdp_handleClientReq(hdr, session, buff, len))
			{
				return opcssdp_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (PARSER_OK != opcssdp_handleServerReq(hdr, session, buff, len))
			{
				return opcssdp_closeSession(hdr, (int)len, "Handle server request data");
			}
		}

		break;
	}

	case FLTEV_ONFWDDATA:       /* Receive data from arbitration-machine */
	{
		ForwardObject *obj = NULL;

		if (NULL == hdr->user)
		{
			SCLogError("[%s:%d]invalid para, hdr(%p), user(%p)", __func__, __LINE__, hdr, hdr->user);
			return opcssdp_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("[%s:%d]invalid para, buff(%p), len(%u)", __func__, __LINE__, buff, (unsigned int)len);
			return opcssdp_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		SCLogInfo("[%s:%d]receive data from fwd, len(%u), sessionid(%u)",
			__func__, __LINE__, (unsigned int)obj->buffdata.len, hdr->sessionid);

		if (PARSER_OK != opcssdp_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != opcssdp_handleClientRsp(hdr, session, obj))
			{
				return opcssdp_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != opcssdp_handleServerRsp(hdr, session, obj))
			{
				return opcssdp_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return opcssdp_closeSession(hdr, 0, NULL);
	}

	default:                    /* Not handle, return ok */
		break;

	}

	return FLTRET_OK;
}

/************************************************************
*Function    : opcssdp_free
*Action      : opcssdp free
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opcssdp_free(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : opcssdp_init
*Action      : opcssdp init
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opcssdp_init(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : opcssdp_checkData
*Action      : opcssdp check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID opcssdp_checkData(const void *buff, size_t len)
{
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_opcssdp
*Action      : opcssdp protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static struct packet_filter g_filter_opcssdp =
{
	SVR_ID_OPCSSDP,
	"opcssdp parser",
	opcssdp_init,
	opcssdp_data,
	opcssdp_free,
	opcssdp_checkData
};

void parser_opc_ssdp_pktfilter_reg()
{
	pktfilter_reg(&g_filter_opcssdp);
}

void parser_opc_ssdp_pktfilter_unreg()
{
	pktfilter_unreg(&g_filter_opcssdp);
}