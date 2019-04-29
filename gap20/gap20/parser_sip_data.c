#include "app_common.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gap_stgy.h"
#include "gapconfig.h"
#include "parser_tcp.h"
#include "parser_common.h"
#include "parser_sip.h"

/************************************************************
*Function    : sipdata_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static SIP_DATA_SESSION *sipdata_allocSession(void)
{
	SIP_DATA_SESSION *session = NULL;

	session = SCMalloc(sizeof(SIP_DATA_SESSION));
	if (NULL == session)
	{
		SCLogError("SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)sizeof(SIP_DATA_SESSION), __func__, __LINE__);
		return NULL;
	}

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
	return session;
}

/************************************************************
*Function    : sipdata_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static void sipdata_freeSession(SIP_DATA_SESSION *session)
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
*Function    : sipdata_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET sipdata_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	SIP_DATA_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogError("invalid para, hdr(%p), user(%p), maybe session is closed[%s:%d]", hdr, hdr->user, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		sip_writeSeceventLog(hdr, packLen, content, SVR_ID_SIPDATA);
	}

	session = hdr->user;

	SCLogInfo("on socket close, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);

	sipdata_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

/************************************************************
*Function    : sipdata_handleClientReq
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
static int sipdata_handleClientReq(struct filter_header *hdr, SIP_DATA_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Send request event buffer */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("add data to session req buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send request buffer */
		if ((NULL != buff) && (0 < len))
		{
			if (0 != buffer_sendtofwd(hdr, buff, len))
			{
				SCLogError("send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sipdata_handleServerReq
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
static int sipdata_handleServerReq(struct filter_header *hdr, SIP_DATA_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Send request event buffer */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("add data to session req buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send request buffer */
		if ((NULL != buff) && (0 < len))
		{
			if (0 != buffer_sendtofwd(hdr, buff, len))
			{
				SCLogError("send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sipdata_checkFwdObjData
*Action      : check form forward obj data
*Input       : hdr          packet processing header information
			   obj          data obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int sipdata_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
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

/************************************************************
*Function    : sipdata_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int sipdata_handleClientRsp(struct filter_header *hdr, SIP_DATA_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		/* Send response event buffer */
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
			SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
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

/************************************************************
*Function    : sipdata_handleServerRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int sipdata_handleServerRsp(struct filter_header *hdr, SIP_DATA_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		/* Send response event buffer */
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
			SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
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

/************************************************************
*Function    : sipdata_data
*Action      : SIPDATA protocol data processing
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
static enum FLT_RET sipdata_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SIP_DATA_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("invalid para, hdr(%p)[%s:%d]", hdr, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = sipdata_allocSession();
		if (session == NULL)
		{
			SCLogError("create new sip session failed, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		SCLogInfo("connect in, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		break;
	}

	case FLTEV_ONSOCKDATA:      /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("invalid para, hdr(%p), user(%p)[%s:%d]", hdr, hdr->user, __func__, __LINE__);
			return sipdata_closeSession(hdr, (int)len, "User data is NULL");
		}

		session = hdr->user;

		//SCLogInfo("receive data from req, len(%u), sessionid(%u)[%s:%d]",
		//           (unsigned int)len, hdr->sessionid, __func__, __LINE__);

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != sipdata_handleClientReq(hdr, session, buff, len))
			{
				return sipdata_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (PARSER_OK != sipdata_handleServerReq(hdr, session, buff, len))
			{
				return sipdata_closeSession(hdr, (int)len, "Handle server request data");
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
			return sipdata_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("invalid para, buff(%p), len(%u)[%s:%d]", buff, (unsigned int)len, __func__, __LINE__);
			return sipdata_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		//SCLogInfo("receive data from fwd, len(%u), sessionid(%u)[%s:%d]",
		//           (unsigned int)obj->buffdata.len,hdr->sessionid, __func__, __LINE__);

		if (PARSER_OK != sipdata_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != sipdata_handleClientRsp(hdr, session, obj))
			{
				return sipdata_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != sipdata_handleServerRsp(hdr, session, obj))
			{
				return sipdata_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return sipdata_closeSession(hdr, 0, NULL);
	}

	case FLTEV_ONSVROK:         /* Not handle, return ok */
	default:
		break;

	}

	return FLTRET_OK;
}

/************************************************************
*Function    : sipdata_free
*Action      : sip data free
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int sipdata_free(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : sipdata_init
*Action      : sip data init
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int sipdata_init(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : sipdata_checkData
*Action      : sipdata check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID sipdata_checkData(const void *buff, size_t len)
{
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_sipdata
*Action      : sip data protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static struct packet_filter g_filter_sip_data =
{
	SVR_ID_SIPDATA,
	"sip data parser",
	sipdata_init,
	sipdata_data,
	sipdata_free,
	sipdata_checkData
};

PROTOCOL_FILTER_OP(sip_data)

