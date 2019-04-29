#include "app_common.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gap_stgy.h"
#include "gapconfig.h"
#include "parser_tcp.h"
#include "parser_common.h"
#include "parser_rtsp.h"

/************************************************************
*Function    : rtspdata_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static RTSP_DATA_SESSION *rtspdata_allocSession(void)
{
	RTSP_DATA_SESSION *session = NULL;

	session = SCMalloc(sizeof(RTSP_DATA_SESSION));
	if (NULL == session)
	{
		SCLogError("[RTSPDATA]SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)sizeof(RTSP_DATA_SESSION), __func__, __LINE__);
		return NULL;
	}

	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("[RTSPDATA]evbuffer_new failed[%s:%d]", __func__, __LINE__);
		SCFree(session);
		session = NULL;
		return NULL;
	}

	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("[RTSPDATA]evbuffer_new failed[%s:%d]", __func__, __LINE__);
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}
	return session;
}

/************************************************************
*Function    : rtspdata_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static void rtspdata_freeSession(RTSP_DATA_SESSION *session)
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
*Function    : rtspdata_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET rtspdata_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	RTSP_DATA_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogError("[RTSPDATA]invalid para, hdr(%p), user(%p), maybe session is closed[%s:%d]", hdr, hdr->user, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		rtsp_writeSeceventLog(hdr, packLen, content, SVR_ID_RTSP);
	}

	session = hdr->user;

	SCLogInfo("[RTSPDATA]on socket close, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);

	rtspdata_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

/************************************************************
*Function    : rtspdata_handleClientReq
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
static int rtspdata_handleClientReq(struct filter_header *hdr, RTSP_DATA_SESSION *session, const void *buff, size_t len)
{
	size_t eventBufLen;

	eventBufLen = evbuffer_get_length(session->reqBuf);
	if (0 < eventBufLen)
	{
		/* Send request event buffer */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[RTSPDATA]add data to session req buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		//SCLogInfo("[RTSPDATA]send to fwd, len(%u), ssid(%u)[%s:%d]", (unsigned int)(eventBufLen), hdr->sessionid, __func__, __LINE__);
		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[RTSPDATA]send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send request buffer */
		if ((NULL != buff) && (0 < len))
		{
			//SCLogInfo("[RTSPDATA]send to fwd, len(%u), ssid(%u)[%s:%d]", (unsigned int)(len), hdr->sessionid, __func__, __LINE__);
			if (0 != buffer_sendtofwd(hdr, buff, len))
			{
				SCLogError("[RTSPDATA]send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtspdata_handleServerReq
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
static int rtspdata_handleServerReq(struct filter_header *hdr, RTSP_DATA_SESSION *session, const void *buff, size_t len)
{
	return rtspdata_handleClientReq(hdr, session, buff, len);
}

/************************************************************
*Function    : rtspdata_checkFwdObjData
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
static int rtspdata_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
{
	if (obj->cmd != FWDCMD_FORWARDDATA)
	{
		SCLogError("[RTSPDATA]not fwd event type, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (0 == obj->has_buffdata)
	{
		SCLogError("[RTSPDATA]obj data is null, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtspdata_handleClientRsp
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
static int rtspdata_handleClientRsp(struct filter_header *hdr, RTSP_DATA_SESSION *session, ForwardObject *obj)
{
	size_t eventBufLen;

	eventBufLen = evbuffer_get_length(session->rspBuf);
	if (0 < eventBufLen)
	{
		/* Send response event buffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[RTSPDATA]add data to session rsp buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		//SCLogInfo("[RTSPDATA]send to req, len(%u), ssid(%u)[%s:%d]", (unsigned int)(eventBufLen), hdr->sessionid, __func__, __LINE__);
		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
		{
			SCLogError("[RTSPDATA]send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send response buffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			//SCLogInfo("[RTSPDATA]send to req, len(%u), ssid(%u)[%s:%d]", (unsigned int)(obj->buffdata.len), hdr->sessionid, __func__, __LINE__);
			if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[RTSPDATA]send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtspdata_handleServerRsp
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
static int rtspdata_handleServerRsp(struct filter_header *hdr, RTSP_DATA_SESSION *session, ForwardObject *obj)
{
	return rtspdata_handleClientRsp(hdr, session, obj);
}

/************************************************************
*Function    : rtspdata_data
*Action      : RTSPDATA protocol data processing
*Input       : hdr  packet processing header information
			   ev   data packet processing type
			   buff data
			   len  data len
*Output      : null
*Return      : FLT_RET
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static enum FLT_RET rtspdata_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	RTSP_DATA_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("[RTSPDATA]invalid para, hdr(%p)[%s:%d]", hdr, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = rtspdata_allocSession();
		if (session == NULL)
		{
			SCLogError("[RTSPDATA]create new rtsp session failed, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		hdr->timeout = 100000000;
		SCLogInfo("[RTSPDATA]connect in, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		break;
	}

	case FLTEV_ONSOCKDATA:      /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[RTSPDATA]invalid para, hdr(%p), user(%p)[%s:%d]", hdr, hdr->user, __func__, __LINE__);
			return rtspdata_closeSession(hdr, (int)len, "User data is NULL");
		}

		session = hdr->user;

		//SCLogInfo("[RTSPDATA]receive data from req, len(%u), sessionid(%u)[%s:%d]",
		//           (unsigned int)len, hdr->sessionid, __func__, __LINE__);

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != rtspdata_handleClientReq(hdr, session, buff, len))
			{
				return rtspdata_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (PARSER_OK != rtspdata_handleServerReq(hdr, session, buff, len))
			{
				return rtspdata_closeSession(hdr, (int)len, "Handle server request data");
			}
		}

		break;
	}

	case FLTEV_ONFWDDATA:       /* Receive data from arbitration-machine */
	{
		ForwardObject *obj = NULL;

		if (NULL == hdr->user)
		{
			SCLogError("[RTSPDATA]invalid para, hdr(%p), user(%p)[%s:%d]", hdr, hdr->user, __func__, __LINE__);
			return rtspdata_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("[RTSPDATA]invalid para, buff(%p), len(%u)[%s:%d]", buff, (unsigned int)len, __func__, __LINE__);
			return rtspdata_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		//SCLogInfo("[RTSPDATA]receive data from fwd, len(%u), sessionid(%u)[%s:%d]",
		//           (unsigned int)obj->buffdata.len,hdr->sessionid, __func__, __LINE__);

		if (PARSER_OK != rtspdata_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != rtspdata_handleClientRsp(hdr, session, obj))
			{
				return rtspdata_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != rtspdata_handleServerRsp(hdr, session, obj))
			{
				return rtspdata_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return rtspdata_closeSession(hdr, 0, NULL);
	}

	case FLTEV_ONSVROK:         /* Not handle, return ok */
	default:
	{
		break;
	}

	}

	return FLTRET_OK;
}

/************************************************************
*Function    : rtspdata_free
*Action      : rtsp data free
*Input       : null
*Output      : null
*Return      : FLT_RET
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int rtspdata_free(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : rtspdata_init
*Action      : rtsp data init
*Input       : null
*Output      : null
*Return      : FLT_RET
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int rtspdata_init(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : rtspdata_checkData
*Action      : rtspdata check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : SVR_ID
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID rtspdata_checkData(const void *buff, size_t len)
{
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_rtspdata
*Action      : rtsp data protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static struct packet_filter g_filter_rtsp_data =
{
	SVR_ID_RTSPDATA,
	"rtsp data parser",
	rtspdata_init,
	rtspdata_data,
	rtspdata_free,
	rtspdata_checkData
};

PROTOCOL_FILTER_OP(rtsp_data)

