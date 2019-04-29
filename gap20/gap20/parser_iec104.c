/********************************************************************************

		   Copyright (C), 2016, 2016, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_iec104.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2016.12.23
Description    : IEC104 protocol process
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
#include "parser_common.h"

/* Description */
#define IEC104_DESC(X)                 1

/* BOOL definition */
#define IEC104_BTRUE                   (~0)
#define IEC104_BFALSE                  0

/* Return Value definition */
#define IEC104_RETURN_CONTINUE         1
#define IEC104_RETURN_OK               0
#define IEC104_RETURN_ERROR            (-1)

/* IEC104 IP cache size */
#define IEC104_IP_BUFF_SIZE            64

/* APCI data length */
#define IEC104_APCI_LEN                6

/* Head length */
#define IEC104_HEAD_LEN                2

/* APDU data max-length */
#define IEC104_MAX_APDU_LEN            253

/* APDU start-Byte */
#define IEC104_APDU_START_KEY          0x68

/* APDU fixed frame length */
#define IEC104_APDU_FIXED_FRAME_LEN    0x04

/* Application packet cache size */
#define IEC104_BUFF_DATA_LEN           10240

/* Gets or sets the finger position */
#define IEC104_GET_BIT(x, n)           (1 & (x >> n))
#define IEC104_SET_BIT(x, n)           (x = (1 << n) | x)

/* Session connection status */
typedef enum IEC104_CONNECT_STATUS_E
{
	IEC104_DISCONNECT = 0,
	IEC104_CONNECTING,
	IEC104_CONNECTED
} IEC104_CONNECT_STATUS;

/* Data processing rule */
typedef enum IEC104_DATA_RULE_E
{
	IEC104_DATA_NORMAL = 0,
	IEC104_DATA_DROP,
	IEC104_DATA_CLOSE
} IEC104_DATA_RULE;

/* Data type */
typedef enum IEC104_DATA_TYPE_E
{
	IEC104_DATA_REQ = 0,
	IEC104_DATA_RSP
} IEC104_DATA_TYPE_E;

/* IEC104 session information */
typedef struct IEC104_SESSION_S
{
	int connecting;
	char isReqbufSend;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} IEC104_SESSION;

/* IEC104 APCI struction */
typedef struct IEC104_APCI_S
{
	unsigned char startKey;
	unsigned char apduLen;
	unsigned char controlDomain1;
	unsigned char controlDomain2;
	unsigned char controlDomain3;
	unsigned char controlDomain4;
} IEC104_APCI;

/* IEC104 APDU struction */
typedef struct IEC104_APDU_S
{
	IEC104_APCI apci;
	char *asdu;
} IEC104_APDU_S;

/************************************************************
*Function    : iec104_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static IEC104_SESSION *iec104_allocSession(void)
{
	IEC104_SESSION *session = NULL;

	session = SCMalloc(sizeof(IEC104_SESSION));
	if (NULL == session)
	{
		SCLogError("IEC104[ERROR]: SCMalloc memory failed, size(%u)", (unsigned int)sizeof(IEC104_SESSION));
		return NULL;
	}

	memset(session, 0, sizeof(*session));

	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("IEC104[ERROR]: evbuffer_new failed");
		SCFree(session);
		session = NULL;
		return NULL;
	}

	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("IEC104[ERROR]: evbuffer_new failed");
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}

	session->connecting = IEC104_DISCONNECT;
	session->isReqbufSend = IEC104_BFALSE;
	return session;
}

/************************************************************
*Function    : iec104_freeSession
*Action      : free session
*Input       : session  session obj
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static void iec104_freeSession(IEC104_SESSION *session)
{
	if (NULL == session)
	{
		return;
	}

	if (session->rspBuf)
	{
		evbuffer_free(session->rspBuf);
		session->rspBuf = NULL;
	}

	if (session->reqBuf)
	{
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
	}

	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : iec104_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void iec104_writeSeceventLog(struct filter_header *hdr, int packLen, char *content)
{
	char sip[IEC104_IP_BUFF_SIZE];
	char dip[IEC104_IP_BUFF_SIZE];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	proto = (char*)server_strfromid(SVR_ID_IEC104);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
		aclData->user, "none", l_critical, aclData->groupname, "false", packLen, content);
}

/************************************************************
*Function    : iec104_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET iec104_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	IEC104_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogWarning("IEC104[WARN]: invalid para, hdr(%p), user(%p), maybe session is closed", hdr, hdr->user);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		iec104_writeSeceventLog(hdr, packLen, content);
	}

	session = hdr->user;

	SCLogInfo("IEC104[INFO]: on socket close, ssid(%u)", hdr->sessionid);

	iec104_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

/************************************************************
*Function    : iec104_sendReqBufData
*Action      : send session req cache data
*Input       : hdr      packet processing header information
			   session  session obj
*Output      : null
*Return      : IEC104_RETURN_OK    success
			   IEC104_RETURN_ERROR false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int iec104_sendReqBufData(struct filter_header *hdr, IEC104_SESSION *session)
{
	ev_ssize_t ret;
	size_t reqBufLen;
	IEC104_APCI iec104Apci;
	unsigned char content[IEC104_BUFF_DATA_LEN];

	if (session->isReqbufSend)
	{
		return IEC104_RETURN_OK;
	}

	while (1)
	{
		reqBufLen = evbuffer_get_length(session->reqBuf);
		if (0 >= reqBufLen)
		{
			SCLogInfo("IEC104[INFO]: req buff len is %u, do not send, ssid(%u)",
				(unsigned int)reqBufLen, hdr->sessionid);
			break;
		}

		if (IEC104_APCI_LEN >= reqBufLen)
		{
			ret = evbuffer_copyout(session->reqBuf, (void *)content, reqBufLen);
			if (-1 == ret)
			{
				SCLogError("IEC104[ERROR]: copy data from req buff failed, ssid(%u)", hdr->sessionid);
				return IEC104_RETURN_ERROR;
			}

			SCLogInfo("IEC104[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)reqBufLen, hdr->sessionid);

			if (0 != buffer_sendtofwd(hdr, content, reqBufLen))
			{
				SCLogError("IEC104[ERROR]: evbuffer send to forward by len failed, ssid(%u)", hdr->sessionid);
				return IEC104_RETURN_ERROR;;
			}

			break;
		}

		ret = evbuffer_copyout(session->reqBuf, (void *)&iec104Apci, sizeof(IEC104_APCI));
		if (-1 == ret)
		{
			SCLogError("IEC104[ERROR]: copy data from req buff failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}

		/* check start-byte */
		if (IEC104_APDU_START_KEY != iec104Apci.startKey)
		{
			SCLogError("IEC104[ERROR]: invalid apdu start key(0x%x), need(0x%02x)",
				iec104Apci.startKey, IEC104_APDU_START_KEY);
			if (0 != evbuffer_drain(session->reqBuf, reqBufLen))
			{
				return IEC104_RETURN_ERROR;
			}
			else
			{
				/* Data validation failed, discard data */
				break;
			}
		}

		SCLogInfo("IEC104[INFO]: reqBufLen(%u), fragLength(%u), ssid(%u)",
			(unsigned int)reqBufLen, iec104Apci.apduLen, hdr->sessionid);

		if (reqBufLen < iec104Apci.apduLen)
		{
			/* Processing the last incomplete fragment of session data */

			/*
			   If no valid data fragment is found, copy out this segment,
			   send to arbitration-machine, avoid data cache time too long
		   */
			ret = evbuffer_copyout(session->reqBuf, (void *)content, reqBufLen);
			if (-1 == ret)
			{
				SCLogError("IEC104[ERROR]: copy data from req buff failed, ssid(%u)", hdr->sessionid);
				return IEC104_RETURN_ERROR;
			}

			SCLogInfo("IEC104[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)reqBufLen, hdr->sessionid);

			if (0 != buffer_sendtofwd(hdr, content, reqBufLen))
			{
				SCLogError("IEC104[ERROR]: evbuffer send to forward by len failed, ssid(%u)", hdr->sessionid);
				return IEC104_RETURN_ERROR;;
			}

			/* Data processing completed of eventbuf, out of circulation return */
			break;
		}

		SCLogInfo("IEC104[INFO]: send to fwd, len(%u), ssid(%u)", iec104Apci.apduLen + IEC104_HEAD_LEN, hdr->sessionid);

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, (size_t)(iec104Apci.apduLen + IEC104_HEAD_LEN)))
		{
			SCLogError("IEC104[ERROR]: evbuffer send to forward by len failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;;
		}
	}

	session->isReqbufSend = IEC104_BTRUE;
	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_drainEventBuf
*Action      : remove data from event buffer
*Input       : eventBuf     event buffer
			   eventBufLen  event buffer len
			   dataRule     data rule
*Output      : null
*Return      : IEC104_RETURN_OK    success
			   IEC104_RETURN_ERROR false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_drainEventBuf(struct evbuffer *eventBuf, size_t eventBufLen, char *dataRule)
{
	if (0 != evbuffer_drain(eventBuf, eventBufLen))
	{
		return IEC104_RETURN_ERROR;
	}
	else
	{
		/* Data validation failed, discard data */
		*dataRule = IEC104_DATA_DROP;
		return IEC104_RETURN_OK;
	}
}

/************************************************************
*Function    : iec104_checkReqEvBuffFormat
*Action      : check request data validity of event buffer
*Input       : reqBuf       requeset buffer
			   reqBufLen    requeset buffer len
			   iec104Apci   iec104 apci obj
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
			   IEC104_RETURN_CONTINUE   continue
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_checkReqEvBuffFormat(struct evbuffer *reqBuf, size_t reqBufLen, IEC104_APCI *iec104Apci, char *dataRule)
{
	/* Check start-byte */
	if (IEC104_APDU_START_KEY != iec104Apci->startKey)
	{
		SCLogError("IEC104[ERROR]: invalid apdu start key(0x%x), need(0x%02x)",
			iec104Apci->startKey, IEC104_APDU_START_KEY);
		return iec104_drainEventBuf(reqBuf, reqBufLen, dataRule);
	}

	/* Check data length */
	if (IEC104_MAX_APDU_LEN < iec104Apci->apduLen)
	{
		SCLogError("IEC104[ERROR]: invalid len, apdu len(%u), max(%d)", iec104Apci->apduLen, IEC104_MAX_APDU_LEN);
		return iec104_drainEventBuf(reqBuf, reqBufLen, dataRule);
	}

	/* Check frame type */
	if (1 == IEC104_GET_BIT(iec104Apci->controlDomain1, 0))
	{
		/* Express: S or U format frame, fixed short frame */
		if (IEC104_APDU_FIXED_FRAME_LEN != iec104Apci->apduLen)
		{
			SCLogError("IEC104[ERROR]: invalid len(%u), S or U frame, frame len need(0x04)", iec104Apci->apduLen);
			return iec104_drainEventBuf(reqBuf, reqBufLen, dataRule);
		}
	}
	/* else Express: I format frame, variable frame */

	return IEC104_RETURN_CONTINUE;
}

/************************************************************
*Function    : iec104_checkRspEvBuffFormat
*Action      : check response data validity of event buffer
*Input       : rspBuf       response buffer
			   rspBufLen    response buffer len
			   iec104Apci   iec104 apci obj
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
			   IEC104_RETURN_CONTINUE   continue
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_checkRspEvBuffFormat(struct evbuffer *rspBuf, size_t rspBufLen, IEC104_APCI *iec104Apci, char *dataRule)
{
	/* Check start-byte */
	if (IEC104_APDU_START_KEY != iec104Apci->startKey)
	{
		SCLogError("IEC104[ERROR]: invalid apdu start key(0x%x), need(0x%02x)",
			iec104Apci->startKey, IEC104_APDU_START_KEY);
		return iec104_drainEventBuf(rspBuf, rspBufLen, dataRule);
	}

	/* Check data length */
	if (IEC104_MAX_APDU_LEN < iec104Apci->apduLen)
	{
		SCLogError("IEC104[ERROR]: invalid len, apdu len(%u), max(%d)", iec104Apci->apduLen, IEC104_MAX_APDU_LEN);
		return iec104_drainEventBuf(rspBuf, rspBufLen, dataRule);
	}

	/* Check frame type */
	if (1 == IEC104_GET_BIT(iec104Apci->controlDomain1, 0))
	{
		/* Express: S or U format frame, fixed short frame */
		if (IEC104_APDU_FIXED_FRAME_LEN != iec104Apci->apduLen)
		{
			SCLogError("IEC104[ERROR]: invalid len(%u), S or U frame, frame len need(0x04)", iec104Apci->apduLen);
			return iec104_drainEventBuf(rspBuf, rspBufLen, dataRule);
		}
	}
	/* else Express: I format frame, variable frame */

	return IEC104_RETURN_CONTINUE;
}

/************************************************************
*Function    : iec104_checkCompleteSession
*Action      : check the full session in reqbuf
*Input       : dataType     data type
			   hdr          packet processing header information
			   evnetBuf     event buffer
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_checkCompleteSession(char dataType, struct filter_header *hdr, struct evbuffer *evnetBuf, char *dataRule)
{
	int result;
	ev_ssize_t ret;
	size_t eventBufLen;
	IEC104_APCI iec104Apci;

	while (1)
	{
		eventBufLen = evbuffer_get_length(evnetBuf);
		if (0 >= eventBufLen)
		{
			SCLogInfo("IEC104[INFO]: event buff len is %u, do not need analy, ssid(%u)",
				(unsigned int)eventBufLen, hdr->sessionid);
			break;
		}

		if (IEC104_APCI_LEN >= eventBufLen)
		{
			break;
		}

		ret = evbuffer_copyout(evnetBuf, (void *)&iec104Apci, IEC104_APCI_LEN);
		if (-1 == ret)
		{
			SCLogError("IEC104[ERROR]: copy data from event buff failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}

		/* Check data specification */
		if (IEC104_DATA_REQ == dataType)
		{
			result = iec104_checkReqEvBuffFormat(evnetBuf, eventBufLen, &iec104Apci, dataRule);
			if (IEC104_RETURN_CONTINUE != result)
			{
				return result;
			}
		}
		else
		{
			result = iec104_checkRspEvBuffFormat(evnetBuf, eventBufLen, &iec104Apci, dataRule);
			if (IEC104_RETURN_CONTINUE != result)
			{
				return result;
			}
		}

		SCLogInfo("IEC104[INFO]: eventBufLen(%u), fragLength(%u), ssid(%u)",
			(unsigned int)eventBufLen, iec104Apci.apduLen, hdr->sessionid);

		if (eventBufLen < iec104Apci.apduLen)
		{
			/* No complete conversation */
			break;
		}

		/* Delete the analyzed data fragment */
		if (0 != evbuffer_drain(evnetBuf, (size_t)(iec104Apci.apduLen + IEC104_HEAD_LEN)))
		{
			SCLogError("IEC104[ERROR]: drain data from session event buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_analyEventReqbufData
*Action      : analyze session request cache data
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int iec104_analyEventReqbufData(struct filter_header *hdr, IEC104_SESSION *session,
	const void *buff, size_t len, char *dataRule)
{
	int result;
	ev_ssize_t ret;
	size_t totalLen;
	size_t reqBufLen;
	IEC104_APCI iec104Apci;
	unsigned char content[IEC104_BUFF_DATA_LEN];

	reqBufLen = evbuffer_get_length(session->reqBuf);
	ret = evbuffer_copyout(session->reqBuf, (void *)content, reqBufLen);
	if (-1 == ret)
	{
		SCLogError("IEC104[ERROR]: copy data from req buff failed, ssid(%u)", hdr->sessionid);
		return IEC104_RETURN_ERROR;
	}

	memcpy(content + reqBufLen, buff, len);
	totalLen = reqBufLen + len;

	if (IEC104_APCI_LEN > totalLen)
	{
		if (0 != evbuffer_add(session->reqBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
		return IEC104_RETURN_OK;
	}

	memcpy((void *)&iec104Apci, content, IEC104_APCI_LEN);

	result = iec104_checkReqEvBuffFormat(session->reqBuf, reqBufLen, &iec104Apci, dataRule);
	if (IEC104_RETURN_CONTINUE != result)
	{
		return result;
	}

	if (totalLen < iec104Apci.apduLen)
	{
		if (0 != evbuffer_add(session->reqBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
		return IEC104_RETURN_OK;
	}

	/* Delete the analyzed data fragment */
	if ((0 < reqBufLen) && (0 != evbuffer_drain(session->reqBuf, reqBufLen)))
	{
		SCLogError("IEC104[ERROR]: drain data from session req buffer failed, ssid(%u)", hdr->sessionid);
		return IEC104_RETURN_ERROR;
	}

	/* Add data fragment not analyzed */
	if (iec104Apci.apduLen < totalLen)
	{
		if (0 != evbuffer_add(session->reqBuf, content + iec104Apci.apduLen + IEC104_HEAD_LEN,
			(totalLen - (iec104Apci.apduLen + IEC104_HEAD_LEN))))
		{
			SCLogError("IEC104[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	/* Determine whether there are full session data in the cache, if have, at this time analysis */
	if (IEC104_RETURN_OK != iec104_checkCompleteSession(IEC104_DATA_REQ, hdr, session->reqBuf, dataRule))
	{
		return IEC104_RETURN_ERROR;
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_checkReqBuffFormat
*Action      : check request data validity of buffer
*Input       : iec104Apci   iec104 apci obj
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
			   IEC104_RETURN_CONTINUE   continue
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_checkReqBuffFormat(IEC104_APCI *iec104Apci, char *dataRule)
{
	/* check start-byte */
	if (IEC104_APDU_START_KEY != iec104Apci->startKey)
	{
		/* Data validation failed, discard data */
		*dataRule = IEC104_DATA_DROP;
		SCLogError("IEC104[ERROR]: invalid apdu start key(0x%x), need(0x%02x)",
			iec104Apci->startKey, IEC104_APDU_START_KEY);
		return IEC104_RETURN_OK;
	}

	/* Check data length */
	if (IEC104_MAX_APDU_LEN < iec104Apci->apduLen)
	{
		*dataRule = IEC104_DATA_DROP;
		SCLogError("IEC104[ERROR]: invalid len, apdu len(%u), max(%d)", iec104Apci->apduLen, IEC104_MAX_APDU_LEN);
		return IEC104_RETURN_OK;
	}

	/* Check frame type */
	if (1 == IEC104_GET_BIT(iec104Apci->controlDomain1, 0))
	{
		/* Express: S or U format frame, fixed short frame */
		if (IEC104_APDU_FIXED_FRAME_LEN != iec104Apci->apduLen)
		{
			*dataRule = IEC104_DATA_DROP;
			SCLogError("IEC104[ERROR]: invalid len(%u), S or U fram, frame len need(0x04)", iec104Apci->apduLen);
			return IEC104_RETURN_OK;
		}
	}
	/* else Express: I format frame, variable frame */

	return IEC104_RETURN_CONTINUE;
}

/************************************************************
*Function    : iec104_analyReqbufData
*Action      : analyze session request cache data
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int iec104_analyReqbufData(struct filter_header *hdr, IEC104_SESSION *session,
	const void *buff, size_t len, char *dataRule)
{
	int result;
	IEC104_APCI iec104Apci;

	if (IEC104_APCI_LEN > len)
	{
		if (0 != evbuffer_add(session->reqBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
		return IEC104_RETURN_OK;
	}

	memcpy((void *)&iec104Apci, buff, IEC104_APCI_LEN);

	/* Check data specification */
	result = iec104_checkReqBuffFormat(&iec104Apci, dataRule);
	if (IEC104_RETURN_CONTINUE != result)
	{
		return result;
	}

	SCLogInfo("IEC104[INFO]: len(%u), fragLength(%u), ssid(%u)", (unsigned int)len, iec104Apci.apduLen, hdr->sessionid);

	if (len < iec104Apci.apduLen)
	{
		if (0 != evbuffer_add(session->reqBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	/* Add data fragment not analyzed */
	if (iec104Apci.apduLen < len)
	{
		if (0 != evbuffer_add(session->reqBuf, buff + iec104Apci.apduLen + IEC104_HEAD_LEN,
			(len - (iec104Apci.apduLen + IEC104_HEAD_LEN))))
		{
			SCLogError("IEC104[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	/* Determine whether there are full session data in the cache, if have, at this time analysis */
	if (IEC104_RETURN_OK != iec104_checkCompleteSession(IEC104_DATA_REQ, hdr, session->reqBuf, dataRule))
	{
		return IEC104_RETURN_ERROR;
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_analyEventRspbufData
*Action      : analyze session rsp cache data
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int iec104_analyEventRspbufData(struct filter_header *hdr, IEC104_SESSION *session,
	const void *buff, size_t len, char *dataRule)
{
	int result;
	ev_ssize_t ret;
	size_t totalLen;
	size_t rspBufLen;
	IEC104_APCI iec104Apci;
	unsigned char content[IEC104_BUFF_DATA_LEN];

	rspBufLen = evbuffer_get_length(session->rspBuf);
	ret = evbuffer_copyout(session->rspBuf, (void *)content, rspBufLen);
	if (-1 == ret)
	{
		SCLogError("IEC104[ERROR]: copy data from rsp buff failed, ssid(%u)", hdr->sessionid);
		return IEC104_RETURN_ERROR;
	}

	memcpy(content + rspBufLen, buff, len);
	totalLen = rspBufLen + len;

	if (IEC104_APCI_LEN > totalLen)
	{
		if (0 != evbuffer_add(session->rspBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session rsp buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
		return IEC104_RETURN_OK;
	}

	memcpy((void *)&iec104Apci, content, IEC104_APCI_LEN);

	result = iec104_checkRspEvBuffFormat(session->rspBuf, rspBufLen, &iec104Apci, dataRule);
	if (IEC104_RETURN_CONTINUE != result)
	{
		return result;
	}

	if (totalLen < iec104Apci.apduLen)
	{
		if (0 != evbuffer_add(session->rspBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session rsp buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
		return IEC104_RETURN_OK;
	}

	/* Delete the analyzed data fragment */
	if ((0 < rspBufLen) && (0 != evbuffer_drain(session->rspBuf, rspBufLen)))
	{
		SCLogError("IEC104[ERROR]: drain data from session rsp buffer failed, ssid(%u)", hdr->sessionid);
		return IEC104_RETURN_ERROR;
	}

	/* Add data fragment not analyzed */
	if (iec104Apci.apduLen < totalLen)
	{
		if (0 != evbuffer_add(session->rspBuf, content + iec104Apci.apduLen + IEC104_HEAD_LEN,
			(totalLen - (iec104Apci.apduLen + IEC104_HEAD_LEN))))
		{
			SCLogError("IEC104[ERROR]: add data to session rsp buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	/* Determine whether there are full session data in the cache, if have, at this time analysis */
	if (IEC104_RETURN_OK != iec104_checkCompleteSession(IEC104_DATA_RSP, hdr, session->rspBuf, dataRule))
	{
		return IEC104_RETURN_ERROR;
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_checkRspBuffFormat
*Action      : check response data validity of buffer
*Input       : iec104Apci   iec104 apci obj
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
			   IEC104_RETURN_CONTINUE   continue
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_checkRspBuffFormat(IEC104_APCI *iec104Apci, char *dataRule)
{
	/* check start-byte */
	if (IEC104_APDU_START_KEY != iec104Apci->startKey)
	{
		/* Data validation failed, discard data */
		*dataRule = IEC104_DATA_DROP;
		SCLogError("IEC104[ERROR]: invalid apdu start key(0x%x), need(0x%02x)",
			iec104Apci->startKey, IEC104_APDU_START_KEY);
		return IEC104_RETURN_OK;
	}

	/* Check data length */
	if (IEC104_MAX_APDU_LEN < iec104Apci->apduLen)
	{
		*dataRule = IEC104_DATA_DROP;
		SCLogError("IEC104[ERROR]: invalid len, apdu len(%u), max(%d)", iec104Apci->apduLen, IEC104_MAX_APDU_LEN);
		return IEC104_RETURN_OK;
	}

	/* Check frame type */
	if (1 == IEC104_GET_BIT(iec104Apci->controlDomain1, 0))
	{
		/* Express: S or U format frame, fixed short frame */
		if (IEC104_APDU_FIXED_FRAME_LEN != iec104Apci->apduLen)
		{
			*dataRule = IEC104_DATA_DROP;
			SCLogError("IEC104[ERROR]: invalid len(%u), S or U fram, frame len need(0x04)", iec104Apci->apduLen);
			return IEC104_RETURN_OK;
		}
	}
	/* else Express: I format frame, variable frame */

	return IEC104_RETURN_CONTINUE;
}

/************************************************************
*Function    : iec104_analyRspbufData
*Action      : analyze session response cache data
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
			   dataRule     data processing rules
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int iec104_analyRspbufData(struct filter_header *hdr, IEC104_SESSION *session,
	const void *buff, size_t len, char *dataRule)
{
	int result;
	IEC104_APCI iec104Apci;

	if (IEC104_APCI_LEN > len)
	{
		if (0 != evbuffer_add(session->rspBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session rsp buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
		return IEC104_RETURN_OK;
	}

	memcpy((void *)&iec104Apci, buff, IEC104_APCI_LEN);

	/* Check data specification */
	result = iec104_checkRspBuffFormat(&iec104Apci, dataRule);
	if (IEC104_RETURN_CONTINUE != result)
	{
		return result;
	}

	SCLogInfo("IEC104[INFO]: len(%u), fragLength(%u), ssid(%u)", (unsigned int)len, iec104Apci.apduLen, hdr->sessionid);

	if (len < iec104Apci.apduLen)
	{
		if (0 != evbuffer_add(session->rspBuf, buff, len))
		{
			SCLogError("IEC104[ERROR]: add data to session rsp buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	/* Add data fragment not analyzed */
	if (iec104Apci.apduLen < len)
	{
		if (0 != evbuffer_add(session->rspBuf, buff + iec104Apci.apduLen + IEC104_HEAD_LEN,
			(len - (iec104Apci.apduLen + IEC104_HEAD_LEN))))
		{
			SCLogError("IEC104[ERROR]: add data to session rsp buffer failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	/* Determine whether there are full session data in the cache, if have, at this time analysis */
	if (IEC104_RETURN_OK != iec104_checkCompleteSession(IEC104_DATA_REQ, hdr, session->rspBuf, dataRule))
	{
		return IEC104_RETURN_ERROR;
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_handleClientReq
*Action      : handle client request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_handleClientReq(struct filter_header *hdr, IEC104_SESSION *session, const void *buff, size_t len)
{
	char dataRule;

	/*
	   Just connect successfully, analyze the data in req eventbuf,
	   here will send all the data in eventbuf complete,
	   which is retained failed to complete the analysis of the previous data
	*/
	if (IEC104_RETURN_OK != iec104_sendReqBufData(hdr, session))
	{
		return IEC104_RETURN_ERROR;
	}

	dataRule = IEC104_DATA_NORMAL;
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		SCLogInfo("IEC104[INFO]: reqbuf have data, ssid(%u)", hdr->sessionid);

		if ((NULL != buff) && (0 < len))
		{
			/* Handle: req buffer and this data */
			if (IEC104_RETURN_OK != iec104_analyEventReqbufData(hdr, session, buff, len, &dataRule))
			{
				return IEC104_RETURN_ERROR;
			}
		}
	}
	else
	{
		if ((NULL != buff) && (0 < len))
		{
			/* Req buffer is null, handle this data */
			if (IEC104_RETURN_OK != iec104_analyReqbufData(hdr, session, buff, len, &dataRule))
			{
				return IEC104_RETURN_ERROR;
			}
		}
	}

	if (IEC104_DATA_NORMAL == dataRule)
	{
		if ((NULL != buff) && (0 < len))
		{
			/* Send this data */
			SCLogInfo("IEC104[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)len, hdr->sessionid);

			if (0 != buffer_sendtofwd(hdr, buff, len))
			{
				SCLogError("IEC104[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
				return IEC104_RETURN_ERROR;
			}
		}
	}
	else if (IEC104_DATA_CLOSE == dataRule)
	{
		return IEC104_RETURN_ERROR;
	}
	/* else drop*/

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_handleServerReq
*Action      : handle server request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_handleServerReq(struct filter_header *hdr, IEC104_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		SCLogInfo("IEC104[INFO]: send to fwd, len(%u), ssid(%u)",
			(unsigned int)evbuffer_get_length(session->reqBuf), hdr->sessionid);

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("IEC104[ERROR]: send session buffer data to forward failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	if ((NULL != buff) && (0 < len))
	{
		/* Send this data */
		SCLogInfo("IEC104[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)len, hdr->sessionid);

		if (0 != buffer_sendtofwd(hdr, buff, len))
		{
			SCLogError("IEC104[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
			return IEC104_RETURN_ERROR;
		}
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_handleClientRsp(ForwardObject *obj, struct filter_header *hdr, IEC104_SESSION *session)
{
	char dataRule;

	dataRule = IEC104_DATA_NORMAL;
	if (obj->cmd == FWDCMD_FORWARDDATA)
	{
		if (obj->has_buffdata)
		{
			if (0 < evbuffer_get_length(session->rspBuf))
			{
				SCLogInfo("IEC104[INFO]: rspBuf have data, ssid(%u)", hdr->sessionid);

				if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
				{
					/* Haldle: eventbuf and buff */
					if (IEC104_RETURN_OK != iec104_analyEventRspbufData(hdr, session, obj->buffdata.data,
						obj->buffdata.len, &dataRule))
					{
						return IEC104_RETURN_ERROR;
					}
				}
			}
			else
			{
				if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
				{
					/* No eventbuf data, handle buff */
					if (IEC104_RETURN_OK != iec104_analyRspbufData(hdr, session, obj->buffdata.data,
						obj->buffdata.len, &dataRule))
					{
						return IEC104_RETURN_ERROR;
					}
				}
			}

			if (IEC104_DATA_NORMAL == dataRule)
			{
				if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
				{
					/* Send response data to req */
					SCLogInfo("IEC104[INFO]: send to req, len(%u), ssid(%u)",
						(unsigned int)(obj->buffdata.len), hdr->sessionid);

					if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
					{
						SCLogError("IEC104[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
						return IEC104_RETURN_ERROR;
					}
				}
			}
			else if (IEC104_DATA_CLOSE == dataRule)
			{
				return IEC104_RETURN_ERROR;
			}
			/* else drop */
		}
		else
		{
			SCLogWarning("IEC104[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
		}
	}
	else
	{
		SCLogWarning("IEC104[WARN]: not fwd event type, sessionid(%u)", hdr->sessionid);
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_handleServerRsp
*Action      : handle server response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_handleServerRsp(ForwardObject *obj, struct filter_header *hdr, IEC104_SESSION *session)
{
	if (obj->cmd == FWDCMD_FORWARDDATA)
	{
		if (obj->has_buffdata)
		{
			SCLogInfo("IEC104[INFO]: on fwd data, len(%u), sessionid(%u)", (unsigned int)obj->buffdata.len, hdr->sessionid);

			if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
			{
				SCLogInfo("IEC104[INFO]: sent to req, len(%u), sessionid(%u)",
					(unsigned int)(obj->buffdata.len), hdr->sessionid);

				if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
				{
					SCLogError("IEC104[ERROR]: req callback failed, sessionid(%u)", hdr->sessionid);
					return IEC104_RETURN_ERROR;
				}
			}
			else
			{
				SCLogWarning("IEC104[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
			}
		}
		else
		{
			SCLogWarning("IEC104[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
		}
	}
	else
	{
		SCLogWarning("IEC104[WARN]: not fwd event type, sessionid(%u)", hdr->sessionid);
	}

	return IEC104_RETURN_OK;
}

/************************************************************
*Function    : iec104_data
*Action      : IEC104 protocol data processing
*Input       : hdr  packet processing header information
			   ev   data packet processing type
			   buff data
			   len  data len
*Output      : null
*Return      : FLTRET_CLOSE     close session
			   FLTRET_OK        normal processing
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET iec104_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	IEC104_SESSION *session = NULL;

	if (ev == FLTEV_ONCLIIN)
	{
		/* To connect server */

		if (NULL == hdr)
		{
			SCLogError("IEC104[ERROR]: invalid para, hdr(%p)", hdr);
			return FLTRET_CLOSE;
		}

		session = iec104_allocSession();
		if (session == NULL)
		{
			SCLogError("IEC104[ERROR]: create new iec104 session failed, ssid(%u)", hdr->sessionid);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		session->connecting = IEC104_CONNECTING;
		SCLogInfo("IEC104[INFO]: connect in, ssid(%u)", hdr->sessionid);
	}
	else if (ev == FLTEV_ONSVROK)
	{
		/* Connect to server success or failure */

		int isok;

		if ((NULL == hdr) || (NULL == hdr->user))
		{
			SCLogError("IEC104[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return FLTRET_OK;
		}

		if ((NULL == buff) || ((unsigned int)sizeof(isok) != (unsigned int)len))
		{
			SCLogError("IEC104[ERROR]: invalid para, buff(%p), len(%u)", buff, (unsigned int)len);
			return FLTRET_OK;
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			/* Zero: connection failed */
			SCLogError("IEC104[ERROR]: connect server failed, sock(%d), ssid(%u)", isok, hdr->sessionid);
			return iec104_closeSession(hdr, (int)len, "Check isock");
		}

		SCLogInfo("IEC104[INFO]: connect server success, sock(%d), ssid(%u)", isok, hdr->sessionid);

		session = hdr->user;
		session->connecting = IEC104_CONNECTED;

		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return iec104_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}
	}
	else if (ev == FLTEV_ONSOCKDATA)
	{
		/* Receive client or server data */

		if ((NULL == hdr) || (NULL == hdr->user))
		{
			SCLogError("IEC104[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return FLTRET_OK;
		}

		session = hdr->user;

		SCLogInfo("IEC104[INFO]: on socket data, len(%d), ssid(%u)", (int)len, hdr->sessionid);

		if (IEC104_DISCONNECT == session->connecting)
		{
			/* Has not handshake, receive data, not handle */
			SCLogWarning("IEC104[WARN]: svr not connect, not progress.... ssid(%u)", hdr->sessionid);
			return FLTRET_OK;
		}
		else if (IEC104_CONNECTING == session->connecting)
		{
			if ((NULL != buff) && (0 < len))
			{
				/* Connecting, receive data, add to req buffer, when connected and brush out */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("IEC104[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
					return iec104_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("IEC104[INFO]: svr not ready, delay.... ssid(%u)", hdr->sessionid);
			}
			else
			{
				/* Data abnormal, not handle */
				SCLogWarning("IEC104[WARN]: invalid buffer, buffer(%p), len(%u), ssid(%u)",
					buff, (unsigned int)len, hdr->sessionid);
			}
			return FLTRET_OK;
		}
		else if (IEC104_CONNECTED == session->connecting)
		{
			if (NULL != hdr->svr)
			{
				if (IEC104_RETURN_OK != iec104_handleClientReq(hdr, session, buff, len))
				{
					return iec104_closeSession(hdr, (int)len, "Handle client request data");
				}
			}
			else
			{
				if (IEC104_RETURN_OK != iec104_handleServerReq(hdr, session, buff, len))
				{
					return iec104_closeSession(hdr, (int)len, "Handle server request data");
				}
			}
		}
		else
		{
			/* Unknown state: not handle */
			SCLogWarning("IEC104[WARN]: invalid connetcion status(%d), ssid(%u)",
				session->connecting, hdr->sessionid);
		}
	}
	else if (ev == FLTEV_ONFWDDATA)
	{
		/* Receive data from arbitration-machine */

		ForwardObject *obj = NULL;

		if ((NULL == hdr) || (NULL == hdr->user))
		{
			SCLogError("IEC104[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return FLTRET_OK;
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("IEC104[ERROR]: invalid para, buff(%p), len(%u)", buff, (unsigned int)len);
			return FLTRET_OK;
		}

		session = hdr->user;
		obj = (ForwardObject *)buff;

		SCLogInfo("IEC104[INFO]: receive data from fwd, len(%u), sessionid(%u)",
			(unsigned int)obj->buffdata.len, hdr->sessionid);

		if (NULL != hdr->svr)
		{
			if (IEC104_RETURN_OK != iec104_handleClientRsp(obj, hdr, session))
			{
				return iec104_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (IEC104_RETURN_OK != iec104_handleServerRsp(obj, hdr, session))
			{
				return iec104_closeSession(hdr, (int)len, "Handle server response data");
			}
		}
	}
	else if (ev == FLTEV_ONSOCKERROR)
	{
		/* Close session */
		return iec104_closeSession(hdr, 0, NULL);
	}
	/* else not handle, return ok */

	return FLTRET_OK;
}

/************************************************************
*Function    : iec104_free
*Action      : IEC104 free
*Input       : null
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_free(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : iec104_init
*Action      : IEC104 init
*Input       : null
*Output      : null
*Return      : IEC104_RETURN_OK         success
			   IEC104_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int iec104_init(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : iec104_checkData
*Action      : iec104 check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID iec104_checkData(const void *buff, size_t len)
{
	if ((1 < len) && !memcmp(buff, "\x68", 1))
	{
		return SVR_ID_IEC104;
	}
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_iec104
*Action      : IEC104 protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static struct packet_filter g_filter_iec104 =
{
	SVR_ID_IEC104,
	"iec104 parser",
	iec104_init,
	iec104_data,
	iec104_free,
	iec104_checkData
};

PROTOCOL_FILTER_OP(iec104)