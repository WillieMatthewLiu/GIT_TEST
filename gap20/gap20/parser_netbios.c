/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_netbios.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.2.7
Description    : netbios protocol process
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
#define NETBIOS_DESC(X)                 1

/* BOOL definition */
#define NETBIOS_BTRUE                   ~0
#define NETBIOS_BFALSE                  0

/* Return Value definition */
#define NETBIOS_RETURN_OK               0
#define NETBIOS_RETURN_ERROR            (-1)
#define NETBIOS_RETURN_CONTINUE         1

/* IP address cache size */
#define NETBIOS_IP_BUFF_SIZE            64

/* NETBIOS header length */
#define NETBIOS_HEADER_LENGTH           4

/* NETBIOS smb-component length */
#define NETBIOS_SMB_COMP_LENGTH         4

/* NETBIOS command length */
#define NETBIOS_COMMAND_LENGTH          2

/* NETBIOS ffsmb command offset */
#define NETBIOS_FFSMB_COMMAND_OFFSET    0

/* NETBIOS fesmb command offset */
#define NETBIOS_FESMB_COMMAND_OFFSET    12

/* NETBIOS min-analy length */
#define NETBIOS_ANALY_MIN_LENGTH        34

/* NETBIOS start sign length */
#define NETBIOS_START_SIGN_LEN          4

/* NETBIOS end sign length */
#define NETBIOS_END_SIGN_LEN            2

/* NETBIOS application cache size */
#define NETBIOS_BUFF_DATA_LEN           1536

/* Session connection status */
typedef enum NETBIOS_CONNECT_STATUS_E
{
	NETBIOS_DISCONNECT = 0,
	NETBIOS_CONNECTING,
	NETBIOS_CONNECTED
} NETBIOS_CONNECT_STATUS;

/* NETBIOS Command opcode */
typedef enum NETBIOS_COMMAND_OP_E
{
	NETBIOS_NEGOTIATE_PROTOCOL = 0,
	NETBIOS_SESSION_SETUP,
	NETBIOS_TREE_CONNECT,
	NETBIOS_CREATE,
	NETBIOS_GETINFO,
	NETBIOS_WRITE,
	NETBIOS_READ,
	NETBIOS_IOCTL,
	NETBIOS_CLOSE,
	NETBIOS_FIND,
	NETBIOS_NOTIFY,
	NETBIOS_TREE_DISCONNECT,
	NETBIOS_COMMAND_BUTT
} NETBIOS_COMMAND_OP;

/* Data processing rule */
typedef enum NETBIOS_DATA_RULE_E
{
	NETBIOS_DATA_NORMAL = 0,
	NETBIOS_DATA_DROP,
	NETBIOS_DATA_CLOSE
} NETBIOS_DATA_RULE;

/* Session information */
typedef struct NETBIOS_SESSION_S
{
	int connecting;
	unsigned int remainLen;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} NETBIOS_SESSION;

/* Netbios header information */
typedef struct NETBIOS_HEADER_S
{
	unsigned char type;
	unsigned char msgLen[3];
} NETBIOS_HEADER;

/* Configure struct */
typedef struct NETBIOS_CONFIG_S
{
	char dataRule;
} NETBIOS_CONFIG;

/* \\(unicode) */
static unsigned char g_netbiosDataStartSign[NETBIOS_START_SIGN_LEN] = { 0x5c, 0x00, 0x5c, 0x00 };

/* \(unicode) */
static unsigned char g_netbiosDataEndSign[NETBIOS_END_SIGN_LEN] = { 0x5c, 0x00 };

/* FE-SMB Component sign */
static unsigned char g_fesmbComponentSign[NETBIOS_SMB_COMP_LENGTH] = { 0xfe, 0x53, 0x4d, 0x42 };

/* FF-SMB Component sign */
static unsigned char g_ffsmbComponentSign[NETBIOS_SMB_COMP_LENGTH] = { 0xff, 0x53, 0x4d, 0x42 };

/* Netbios command opcode-string */
static unsigned char g_netbiosCommand[NETBIOS_COMMAND_BUTT][NETBIOS_COMMAND_LENGTH] =
{
	{0x00, 0x00},   /**< Negotiate Protocol */
	{0x01, 0x00},   /**< Session Setup      */
	{0x03, 0x00},   /**< Tree Connect       */
	{0x05, 0x00},   /**< Create             */
	{0x10, 0x00},   /**< GetInfo            */
	{0x09, 0x00},   /**< Write              */
	{0x08, 0x00},   /**< Read               */
	{0x0b, 0x00},   /**< Ioctl              */
	{0x06, 0x00},   /**< Close              */
	{0x0e, 0x00},   /**< Find               */
	{0x0f, 0x00},   /**< Notify             */
	{0x04, 0x00},   /**< Tree Disconnect    */
};

/* Configure data */
static NETBIOS_CONFIG g_netbiosConfig;

/************************************************************
*Function    : netbios_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static NETBIOS_SESSION *netbios_allocSession(void)
{
	NETBIOS_SESSION *session = NULL;

	session = SCMalloc(sizeof(NETBIOS_SESSION));
	if (NULL == session)
	{
		SCLogError("[ERROR]: SCMalloc memory failed, size(%u)", (unsigned int)sizeof(NETBIOS_SESSION));
		return NULL;
	}
	memset(session, 0, sizeof(*session));
	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("[ERROR]: evbuffer_new failed");
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("[ERROR]: evbuffer_new failed");
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->remainLen = 0;
	session->connecting = NETBIOS_DISCONNECT;
	return session;
}

/************************************************************
*Function    : netbios_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void netbios_freeSession(NETBIOS_SESSION *session)
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
*Function    : netbios_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void netbios_writeSeceventLog(struct filter_header *hdr, int packLen, char *content)
{
	char sourceIp[NETBIOS_IP_BUFF_SIZE];
	char destIp[NETBIOS_IP_BUFF_SIZE];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;

	addr2str(hdr->ip->saddr, sourceIp);
	addr2str(hdr->ip->daddr, destIp);
	proto = (char*)server_strfromid(SVR_ID_NETBIOS);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);

	INSERT_ACCESSAUDIT_LOG(autoId, sourceIp, destIp, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
		aclData->user, "none", l_critical, aclData->groupname, "false", packLen, content);
}

/************************************************************
*Function    : netbios_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET netbios_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	NETBIOS_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogWarning("[WARN]: invalid para, hdr(%p), user(%p), maybe session is closed", hdr, hdr->user);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		netbios_writeSeceventLog(hdr, packLen, content);
	}

	session = hdr->user;

	SCLogInfo("[INFO]: on socket close, ssid(%u)", hdr->sessionid);

	netbios_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

#if NETBIOS_DESC("client request message")
/************************************************************
*Function    : netbios_handleClientReq
*Action      : handle client request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int netbios_handleClientReq(struct filter_header *hdr, NETBIOS_SESSION *session, const void *buff, size_t len)
{
	/* Send request eventbuffer */
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
	}

	/* Send request buffer */
	if ((NULL != buff) && (0 < len))
	{
		if (0 != buffer_sendtofwd(hdr, buff, len))
		{
			SCLogError("[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
	}
	else
	{
		SCLogWarning("[WARN]: buffer(%p), len(%u), sessionid(%u)", buff, (unsigned int)len, hdr->sessionid);
	}

	return NETBIOS_RETURN_OK;
}
#endif

#if NETBIOS_DESC("server request message")
/************************************************************
*Function    : netbios_handleServerReq
*Action      : handle server request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int netbios_handleServerReq(struct filter_header *hdr, NETBIOS_SESSION *session, const void *buff, size_t len)
{
	/* Send request eventbuffer */
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		SCLogInfo("[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)evbuffer_get_length(session->reqBuf), hdr->sessionid);

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[ERROR]: send session buffer data to forward failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
	}

	/* Send request buffer */
	if ((NULL != buff) && (0 < len))
	{
		SCLogInfo("[INFO]: send to fwd, len(%u), ssid(%u)", (unsigned int)len, hdr->sessionid);

		if (0 != buffer_sendtofwd(hdr, buff, len))
		{
			SCLogError("[ERROR]: send data to forward failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
	}

	return NETBIOS_RETURN_OK;
}
#endif

/************************************************************
*Function    : netbios_checkFwdObjData
*Action      : check form forward obj data
*Input       : hdr          packet processing header information
			   obj          data obj
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.3
*Instruction : null
************************************************************/
static int netbios_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
{
	if (obj->cmd != FWDCMD_FORWARDDATA)
	{
		SCLogWarning("[WARN]: not fwd event type, sessionid(%u)", hdr->sessionid);
		return NETBIOS_RETURN_ERROR;
	}

	if (0 == obj->has_buffdata)
	{
		SCLogWarning("[WARN]: obj data is null, sessionid(%u)", hdr->sessionid);
		return NETBIOS_RETURN_ERROR;
	}

	return NETBIOS_RETURN_OK;
}

/************************************************************
*Function    : netbiosGetUnicodeDip
*Action      : get unicode dest ip
*Input       : dip      dip
*Output      : unicodeDipStr    unicode dip
			   unicodeDipStrLen unicode dip length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.3.9
*Instruction : null
************************************************************/
static void netbiosGetUnicodeDip(unsigned int dip, char *unicodeDipStr, unsigned int *unicodeDipStrLen)
{
	unsigned int len;
	char dipStr[NETBIOS_IP_BUFF_SIZE];

	IP_NUM_TO_STR(dip, dipStr, NETBIOS_IP_BUFF_SIZE);
	len = strlen(dipStr);
	*unicodeDipStrLen = len * 2;
	(void)char2Wide((char *)dipStr, len, unicodeDipStr, NETBIOS_IP_BUFF_SIZE - 1);
	return;
}

/************************************************************
*Function    : netbios_updataAndSendRspData
*Action      : hdr          packet processing header information
			   eventBuf     event buffer
			   data         data
			   len          data length
			   commandType  command type
*Input       : null
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.3.9
*Instruction : null
************************************************************/
static int netbios_updataAndSendRspData(struct filter_header *hdr, struct evbuffer *eventBuf,
	unsigned char *data, unsigned int len,
	NETBIOS_COMMAND_OP commandType)
{
	unsigned int leftLen;
	unsigned int offset;
	unsigned int contentLen;
	unsigned int unicodeDipStrLen;
	char unicodeDipStr[NETBIOS_IP_BUFF_SIZE];
	unsigned char content[NETBIOS_BUFF_DATA_LEN];
	unsigned char *analyStartAddr = NULL;
	unsigned char *analyEndAddr = NULL;

	if (NULL == (analyStartAddr = memnmem(data, len, g_netbiosDataStartSign, NETBIOS_START_SIGN_LEN)))
	{
		if (0 != buffer_sendtoreq(hdr, data, len))
		{
			SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}

		return NETBIOS_RETURN_OK;
	}
	analyStartAddr += NETBIOS_START_SIGN_LEN;

	offset = (unsigned int)(analyStartAddr - data);
	if (NULL == (analyEndAddr = memnmem(analyStartAddr, len - offset, g_netbiosDataEndSign, NETBIOS_END_SIGN_LEN)))
	{
		if (0 != buffer_sendtoreq(hdr, data, len))
		{
			SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}

		return NETBIOS_RETURN_OK;
	}

	switch (commandType)
	{
	default:
	{
		/* NETBIOS_TREE_CONNECT */
		netbiosGetUnicodeDip((unsigned int)hdr->ip->daddr, unicodeDipStr, &unicodeDipStrLen);
		leftLen = (unsigned int)(analyEndAddr - data);
		leftLen = len - leftLen;
		memcpy(content, data, offset);
		memcpy(content + offset, unicodeDipStr, unicodeDipStrLen);
		memcpy(content + offset + unicodeDipStrLen, analyEndAddr, leftLen);
		contentLen = offset + unicodeDipStrLen + leftLen;

		/* updata message length info */
		offset = (unsigned int)(analyEndAddr - analyStartAddr);
		if (offset != unicodeDipStrLen)
		{
			/* len != contentLen */

			/* updata total length */
			offset = htonl(contentLen);
			memcpy(content + 1, (unsigned char *)&offset + 1, 3);   /**< 1:total length offset   3:total length byte-number */

			/* update path length */
			offset = unicodeDipStrLen + leftLen + NETBIOS_START_SIGN_LEN;
			offset = htonl(offset);         /**< path length information is little-end */
			*(analyStartAddr - NETBIOS_START_SIGN_LEN - 2) = *((unsigned char *)&offset + 3);   /**< 2:first byte of path */
			*(analyStartAddr - NETBIOS_START_SIGN_LEN - 1) = *((unsigned char *)&offset + 2);   /**< 1:second byte of path */

		}

		if (0 != buffer_sendtoreq(hdr, content, contentLen))
		{
			SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
	}
	}

	return NETBIOS_RETURN_OK;
}

#if NETBIOS_DESC("client response message")
/************************************************************
*Function    : netbios_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int netbios_handleClientRsp(struct filter_header *hdr, NETBIOS_SESSION *session, ForwardObject *obj)
{
	/* Send response eventbuffer */
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		SCLogInfo("[INFO]: send to req, len(%u), ssid(%u)", (unsigned int)evbuffer_get_length(session->rspBuf), hdr->sessionid);

		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
		{
			SCLogError("[ERROR]: send session buffer data to req failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
	}

	/* Send response buffer */
	if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
	{
		SCLogInfo("[INFO]: send to req, len(%u), ssid(%u)", (unsigned int)(obj->buffdata.len), hdr->sessionid);

		if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
		{
			SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
	}

	return NETBIOS_RETURN_OK;
}
#endif

#if NETBIOS_DESC("server response message")
/************************************************************
*Function    : netbios_getBigEndianU24
*Action      : big end sequence to U24
*Input       : netValue network value
*Output      : null
*Return      : local value
*Author      : liuzongquan(000932)
*Date        : 2017.3.9
*Instruction : null
************************************************************/
static unsigned int netbios_getBigEndianU24(unsigned char *netValueStr)
{
	return (unsigned int)((*netValueStr << 16) | (*(netValueStr + 1) << 8) | *(netValueStr + 2));
}

/************************************************************
*Function    : netbios_analySvrEventRspbufData
*Action      : updata and send session data
*Input       : hdr          packet processing header information
			   session      session obj
			   msgLen       message length
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.3.9
*Instruction : null
************************************************************/
static int netbios_analySvrEventRspbufData(struct filter_header *hdr, NETBIOS_SESSION *session,
	unsigned int msgLen, NETBIOS_COMMAND_OP commandType)
{
	ev_ssize_t ret;
	unsigned int len;
	unsigned char data[NETBIOS_BUFF_DATA_LEN];

	/* Check message length */
	if (NETBIOS_BUFF_DATA_LEN - NETBIOS_HEADER_LENGTH < msgLen)
	{
		SCLogError("[ERROR]: invalid session data len(%u), ssid(%u)", msgLen, hdr->sessionid);
		return NETBIOS_RETURN_ERROR;
	}

	/* Get analy session data */
	len = msgLen + NETBIOS_HEADER_LENGTH;
	ret = evbuffer_remove(session->rspBuf, data, msgLen + NETBIOS_HEADER_LENGTH);
	if (-1 == ret)
	{
		SCLogError("[ERROR]: copy data from event buff failed, ssid(%u)", hdr->sessionid);
		return NETBIOS_RETURN_ERROR;
	}

	/* Updata and send session data */
	if (NETBIOS_RETURN_OK != netbios_updataAndSendRspData(hdr, session->rspBuf, data, len, commandType))
	{
		return NETBIOS_RETURN_ERROR;
	}

	return NETBIOS_RETURN_OK;
}

/************************************************************
*Function    : netbios_updateSvrEventRspbufData
*Action      : check the full session in rspbuf
*Input       : hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int netbios_updateSvrEventRspbufData(struct filter_header *hdr, NETBIOS_SESSION *session)
{
	ev_ssize_t ret;
	size_t eventBufLen;
	char isCacheSession;
	unsigned int msgLen;
	NETBIOS_COMMAND_OP commandType;
	unsigned char netbiosAnalyData[NETBIOS_ANALY_MIN_LENGTH];

	while (1)
	{
		/* Get data length of client request eventbuffer */
		eventBufLen = evbuffer_get_length(session->rspBuf);
		if (0 >= eventBufLen)
		{
			SCLogInfo("[INFO]: event buff len is %u, do not need analy, ssid(%u)", (unsigned int)eventBufLen, hdr->sessionid);
			break;
		}

		/* Check min-analy data received */
		if (NETBIOS_ANALY_MIN_LENGTH > eventBufLen)
		{
			SCLogInfo("[INFO]: event buff len is %u, min-analy len(%d), ssid(%u)",
				(unsigned int)eventBufLen, NETBIOS_ANALY_MIN_LENGTH, hdr->sessionid);
			break;
		}

		/* Get netbios analy data */
		ret = evbuffer_copyout(session->rspBuf, netbiosAnalyData, NETBIOS_ANALY_MIN_LENGTH);
		if (-1 == ret)
		{
			SCLogError("[ERROR]: copy data from event buff failed, ssid(%u)", hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}

		/* Check message type */
		if (0x00 != netbiosAnalyData[0])
		{
			SCLogError("[ERROR]: invalid message type(%u), ssid(%u)", netbiosAnalyData[0], hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}

		/* Check message component */
		if (!strncmp((void *)(netbiosAnalyData + NETBIOS_HEADER_LENGTH), (void *)g_ffsmbComponentSign, NETBIOS_SMB_COMP_LENGTH))
		{
			isCacheSession = NETBIOS_BFALSE;
		}
		else if (strncmp((void *)(netbiosAnalyData + NETBIOS_HEADER_LENGTH), (void *)g_fesmbComponentSign, NETBIOS_SMB_COMP_LENGTH))
		{
			SCLogError("[ERROR]: invalid message component(%02x %02x %02x %02x), ssid(%u)",
				*(netbiosAnalyData + NETBIOS_HEADER_LENGTH) & 0xff,
				*(netbiosAnalyData + NETBIOS_HEADER_LENGTH + 1) & 0xff,
				*(netbiosAnalyData + NETBIOS_HEADER_LENGTH + 2) & 0xff,
				*(netbiosAnalyData + NETBIOS_HEADER_LENGTH + 3) & 0xff,
				hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
		else
		{
			if (!strncmp((void *)(netbiosAnalyData + NETBIOS_HEADER_LENGTH + NETBIOS_FESMB_COMMAND_OFFSET),
				(void *)g_netbiosCommand[NETBIOS_TREE_CONNECT], NETBIOS_COMMAND_LENGTH))
			{
				isCacheSession = NETBIOS_BTRUE;
				commandType = NETBIOS_TREE_CONNECT;
			}
			else
			{
				isCacheSession = NETBIOS_BFALSE;
				commandType = NETBIOS_COMMAND_BUTT;
			}
		}

		/* Get message length */
		msgLen = netbios_getBigEndianU24(netbiosAnalyData + 1);

		/* Not need analy session */
		if (!isCacheSession)
		{
			if ((msgLen + NETBIOS_HEADER_LENGTH) <= eventBufLen)
			{
				if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, (msgLen + NETBIOS_HEADER_LENGTH)))
				{
					SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
					return NETBIOS_RETURN_ERROR;
				}

				continue;
			}
			else
			{
				if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, eventBufLen))
				{
					SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
					return NETBIOS_RETURN_ERROR;
				}

				session->remainLen = (msgLen + NETBIOS_HEADER_LENGTH) - (unsigned int)eventBufLen;
				break;
			}
		}

		/* Need analy session, check session data all receive */
		if ((msgLen + NETBIOS_HEADER_LENGTH) > eventBufLen)
		{
			SCLogInfo("[INFO]: session data not all receive, ssid(%u)", hdr->sessionid);
			break;
		}

		/* updata and send session data */
		if (NETBIOS_RETURN_OK != netbios_analySvrEventRspbufData(hdr, session, msgLen, commandType))
		{
			return NETBIOS_RETURN_ERROR;
		}
	}

	return NETBIOS_RETURN_OK;
}

/************************************************************
*Function    : netbios_updateSvrRspbufData
*Action      : update the full session in buff
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int netbios_updateSvrRspbufData(struct filter_header *hdr, NETBIOS_SESSION *session, unsigned char *buff, unsigned int len)
{
	char isCacheSession;
	unsigned int msgLen;
	NETBIOS_COMMAND_OP commandType;

	while (1)
	{
		/* Get data length of server response buff */
		if (0 >= len)
		{
			SCLogInfo("[INFO]: buff len is %u, do not need analy, ssid(%u)", (unsigned int)len, hdr->sessionid);
			break;
		}

		/* Check session remainLen */
		if (session->remainLen > 0)
		{
			if (session->remainLen >= len)
			{
				if (0 != buffer_sendtoreq(hdr, buff, len))
				{
					SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
					return NETBIOS_RETURN_ERROR;
				}

				session->remainLen -= len;
				break;
			}
			else
			{
				if (0 != buffer_sendtoreq(hdr, buff, session->remainLen))
				{
					SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
					return NETBIOS_RETURN_ERROR;
				}

				buff += session->remainLen;
				len -= session->remainLen;
				session->remainLen = 0;
			}
		}

		/* Check min-analy data received */
		if (NETBIOS_ANALY_MIN_LENGTH > len)
		{
			if (0 != evbuffer_add(session->rspBuf, buff, len))
			{
				SCLogError("[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
				return NETBIOS_RETURN_ERROR;
			}
			break;
		}

		/* Check message type */
		if (0x00 != buff[0])
		{
			SCLogError("[ERROR]: invalid message type(%u), ssid(%u)", buff[0], hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}

		/* Check message component */
		if (!strncmp((void *)(buff + NETBIOS_HEADER_LENGTH), (void *)g_ffsmbComponentSign, NETBIOS_SMB_COMP_LENGTH))
		{
			isCacheSession = NETBIOS_BFALSE;
		}
		else if (strncmp((void *)(buff + NETBIOS_HEADER_LENGTH), (void *)g_fesmbComponentSign, NETBIOS_SMB_COMP_LENGTH))
		{
			SCLogError("[ERROR]: invalid message component(%02x %02x %02x %02x), ssid(%u)",
				*(buff + NETBIOS_HEADER_LENGTH) & 0xff,
				*(buff + NETBIOS_HEADER_LENGTH + 1) & 0xff,
				*(buff + NETBIOS_HEADER_LENGTH + 2) & 0xff,
				*(buff + NETBIOS_HEADER_LENGTH + 3) & 0xff,
				hdr->sessionid);
			return NETBIOS_RETURN_ERROR;
		}
		else
		{
			if (!strncmp((void *)(buff + NETBIOS_HEADER_LENGTH + NETBIOS_FESMB_COMMAND_OFFSET),
				(void *)g_netbiosCommand[NETBIOS_TREE_CONNECT], NETBIOS_COMMAND_LENGTH))
			{
				isCacheSession = NETBIOS_BTRUE;
				commandType = NETBIOS_TREE_CONNECT;
			}
			else
			{
				isCacheSession = NETBIOS_BFALSE;
				commandType = NETBIOS_COMMAND_BUTT;
			}
		}

		/* Get message length */
		msgLen = netbios_getBigEndianU24(buff + 1);

		/* Not need analy session */
		if (!isCacheSession)
		{
			if ((msgLen + NETBIOS_HEADER_LENGTH) <= len)
			{
				if (0 != buffer_sendtoreq(hdr, buff, (msgLen + NETBIOS_HEADER_LENGTH)))
				{
					SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
					return NETBIOS_RETURN_ERROR;
				}

				buff += (msgLen + NETBIOS_HEADER_LENGTH);
				len -= (msgLen + NETBIOS_HEADER_LENGTH);
				continue;
			}
			else
			{
				if (0 != buffer_sendtoreq(hdr, buff, len))
				{
					SCLogError("[ERROR]: send data to req failed, ssid(%u)", hdr->sessionid);
					return NETBIOS_RETURN_ERROR;
				}

				session->remainLen = (msgLen + NETBIOS_HEADER_LENGTH) - (unsigned int)len;
				break;
			}
		}

		/* Need analy session, check session data all receive */
		if ((msgLen + NETBIOS_HEADER_LENGTH) > len)
		{
			SCLogInfo("[INFO]: session data not all receive, ssid(%u)", hdr->sessionid);
			if (0 != evbuffer_add(session->rspBuf, buff, len))
			{
				SCLogError("[ERROR]: add data to session req buffer failed, ssid(%u)", hdr->sessionid);
				return NETBIOS_RETURN_ERROR;
			}
			break;
		}

		/* Updata and send session data */
		if (NETBIOS_RETURN_OK != netbios_updataAndSendRspData(hdr, session->rspBuf,
			(unsigned char *)buff, (msgLen + NETBIOS_HEADER_LENGTH),
			commandType))
		{
			return NETBIOS_RETURN_ERROR;
		}
		buff += (msgLen + NETBIOS_HEADER_LENGTH);
		len -= (msgLen + NETBIOS_HEADER_LENGTH);
	}

	return NETBIOS_RETURN_OK;
}

/************************************************************
*Function    : netbios_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int netbios_handleServerRsp(struct filter_header *hdr, NETBIOS_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		SCLogInfo("[INFO]: rspbuf have data, ssid(%u)", hdr->sessionid);

		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[ERROR]: add data to session rsp buffer failed, ssid(%u)", hdr->sessionid);
				return NETBIOS_RETURN_ERROR;
			}

			/* Client handle: rsp buffer and this data */
			if (NETBIOS_RETURN_OK != netbios_updateSvrEventRspbufData(hdr, session))
			{
				return NETBIOS_RETURN_ERROR;
			}
		}
		else
		{
			SCLogInfo("[INFO]: buffer(%p), len(%u), sessionid(%u)",
				obj->buffdata.data, (unsigned int)obj->buffdata.len, hdr->sessionid);
		}
	}
	else
	{
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Client handle: this data */
			if (NETBIOS_RETURN_OK != netbios_updateSvrRspbufData(hdr, session,
				(unsigned char *)(obj->buffdata.data),
				(unsigned int)(obj->buffdata.len)))
			{
				return NETBIOS_RETURN_ERROR;
			}
		}
		else
		{
			/* No data */
			SCLogWarning("[WARN]: buffer(%p), len(%u), sessionid(%u)",
				obj->buffdata.data, (unsigned int)obj->buffdata.len, hdr->sessionid);
		}
	}

	return NETBIOS_RETURN_OK;
}
#endif

/************************************************************
*Function    : netbios_data
*Action      : netbios protocol data processing
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
static enum FLT_RET netbios_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	NETBIOS_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("[ERROR]: invalid para, hdr(%p)", hdr);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = netbios_allocSession();
		if (session == NULL)
		{
			SCLogError("[ERROR]: create new session failed, sessionid(%u)", hdr->sessionid);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		session->connecting = NETBIOS_CONNECTING;
		SCLogInfo("[INFO]: connect in, sessionid(%u)", hdr->sessionid);
		break;
	}

	case FLTEV_ONSVROK:         /* Connect to server success or failure */
	{
		int isok;

		if (NULL == hdr->user)
		{
			SCLogError("[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return netbios_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(int) != (unsigned int)len))
		{
			SCLogError("[ERROR]: invalid para, buff(%p), len(%u)", buff, (unsigned int)len);
			return netbios_closeSession(hdr, (int)len, "Invalid socket len");
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			SCLogError("[ERROR]: connect server failed, sock(%d), ssid(%u)", isok, hdr->sessionid);
			return netbios_closeSession(hdr, (int)len, "Invalid socket fd");
		}

		SCLogInfo("[INFO]: connect server success, sock(%d), ssid(%u)", isok, hdr->sessionid);

		session = hdr->user;
		session->connecting = NETBIOS_CONNECTED;
		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return netbios_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}

		break;
	}

	case FLTEV_ONSOCKDATA:      /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return netbios_closeSession(hdr, (int)len, "User data is NULL");
		}

		session = hdr->user;

		SCLogInfo("[INFO]: on socket data, len(%u), sessionid(%u)", (unsigned int)len, hdr->sessionid);

		if (NETBIOS_DISCONNECT == session->connecting)
		{
			/* Has not handshake, receive data, not handle */
			SCLogWarning("[WARN]: svr not connect, not progress.... ssid(%u)", hdr->sessionid);
			return FLTRET_OK;
		}

		if (NETBIOS_CONNECTING == session->connecting)
		{
			if ((NULL != buff) && (0 < len))
			{
				/* Connecting, receive data, add to req buffer, when connected and brush out */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("[ERROR]: add data to session buffer failed, ssid(%u)", hdr->sessionid);
					return netbios_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("[INFO]: svr not ready, delay.... ssid(%u)", hdr->sessionid);
			}
			else
			{
				/* Data abnormal, not handle */
				SCLogWarning("[WARN]: invalid buffer, buffer(%p), len(%u), ssid(%u)",
					buff, (unsigned int)len, hdr->sessionid);
			}
			return FLTRET_OK;
		}

		if (NULL != hdr->svr)
		{
			if (NETBIOS_RETURN_OK != netbios_handleClientReq(hdr, session, buff, len))
			{
				return netbios_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (NETBIOS_RETURN_OK != netbios_handleServerReq(hdr, session, buff, len))
			{
				return netbios_closeSession(hdr, (int)len, "Handle server request data");
			}
		}

		break;
	}

	case FLTEV_ONFWDDATA:       /* Receive data from arbitration-machine */
	{
		ForwardObject *obj = NULL;

		if (NULL == hdr->user)
		{
			SCLogError("[ERROR]: invalid para, hdr(%p), user(%p)", hdr, hdr->user);
			return netbios_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("[ERROR]: invalid para, buff(%p), len(%u)", buff, (unsigned int)len);
			return netbios_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		SCLogInfo("[INFO]: receive data from fwd, len(%u), sessionid(%u)", (unsigned int)obj->buffdata.len, hdr->sessionid);

		if (NETBIOS_RETURN_OK != netbios_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (NETBIOS_RETURN_OK != netbios_handleClientRsp(hdr, session, obj))
			{
				return netbios_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (NETBIOS_RETURN_OK != netbios_handleServerRsp(hdr, session, obj))
			{
				return netbios_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return netbios_closeSession(hdr, 0, NULL);
	}

	default:                    /* Not handle, return ok */
		break;

	}

	return FLTRET_OK;
}

/************************************************************
*Function    : netbios_free
*Action      : netbios free
*Input       : null
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int netbios_free(void)
{
	g_netbiosConfig.dataRule = NETBIOS_DATA_DROP;
	return FLTRET_OK;
}

/************************************************************
*Function    : netbios_init
*Action      : netbios init
*Input       : null
*Output      : null
*Return      : NETBIOS_RETURN_OK         success
			   NETBIOS_RETURN_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int netbios_init(void)
{
	g_netbiosConfig.dataRule = NETBIOS_DATA_DROP;
	return FLTRET_OK;
}

/************************************************************
*Function    : netbios_checkData
*Action      : netbios check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID netbios_checkData(const void *buff, size_t len)
{
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_netbios
*Action      : netbios protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : port 445
************************************************************/
static struct packet_filter g_filter_netbios =
{
	SVR_ID_NETBIOS,
	"netbios parser",
	netbios_init,
	netbios_data,
	netbios_free,
	netbios_checkData
};

void parser_netbios_pktfilter_reg()
{
	pktfilter_reg(&g_filter_netbios);
}

void parser_netbios_pktfilter_unreg()
{
	pktfilter_unreg(&g_filter_netbios);
}