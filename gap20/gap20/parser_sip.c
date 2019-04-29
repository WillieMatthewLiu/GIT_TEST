/********************************************************************************

		   Copyright (C), 2016, 2016, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_sip.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2016.12.28
Description    : SIP protocol process
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
#include "parser_sip.h"

/* System port number */
static unsigned short g_sipDynamicPortNum = 0;

/* Dynamic port service information */
static SIP_DYNAMIC_PORT *g_sipDynamicPort = NULL;

/* Lunch of header */
static SIP_LUNCH g_headerLunch[SIP_HEADER_SUBJECT_ID_BUTT] =
{
	{5,  "Via: "},
	{14, "Max-Forwards: "},
	{9,  "Contact: "},
	{4,  "To: "},
	{6,  "From: "},
	{9,  "Call-ID: "},
	{6,  "CSeq: "},
	{16, "Content-Length: "},
	{18, "WWW-Authenticate: "},
	{21, "Proxy-Authorization: "},
	{15, "Authorization: "},
	{14, "Record-Route: "},
	{7,  "Route: "}
};

/* Lunch of body */
static SIP_LUNCH g_bodyLunch[SIP_BODY_SUBJECT_ID_BUTT] =
{
	{2, "o="},
	{5, "c=IN "},
	{8, "m=audio "},
	{8, "m=video "},
	{6, "a=alt:"}
};

/* Lunch of method */
static SIP_LUNCH g_methodLunch[SIP_METHOD_BUTT] =
{
	{3,  "SIP"},
	{8,  "REGISTER"},
	{9,  "SUBSCRIBE"},
	{6,  "INVITE"},
	{3,  "ACK"},
	{6,  "CANCEL"},
	{3,  "BYE"},
	{7,  "OPTIONS"},
	{4,  "INFO"},
	{5,  "PRACK"},
	{5,  "REFER"},
	{6,  "NOTIFY"},
	{6,  "UPDATE"},
	{7,  "MESSAGE"}
};

/************************************************************
*Function    : sip_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static SIP_SESSION *sip_allocSession(void)
{
	SIP_SESSION *session = NULL;

	session = SCMalloc(sizeof(SIP_SESSION));
	if (NULL == session)
	{
		SCLogError("SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)sizeof(SIP_SESSION), __func__, __LINE__);
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
	session->routes = NULL;
	return session;
}

/************************************************************
*Function    : sip_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void sip_freeSession(SIP_SESSION *session)
{
	SIP_NEW_ROUTE *sipRoute = NULL;

	evbuffer_free(session->rspBuf);
	session->rspBuf = NULL;
	evbuffer_free(session->reqBuf);
	session->reqBuf = NULL;
	while (session->routes)
	{
		sipRoute = session->routes;
		session->routes = sipRoute->next;
		if (sipRoute->data_svr)
		{
			server_free(sipRoute->data_svr);
			sipRoute->data_svr = NULL;
		}
		SCFree(sipRoute);
		sipRoute = NULL;
	}
	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : sip_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
			   svrId    svr id
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
void sip_writeSeceventLog(struct filter_header *hdr, int packLen, char *content, enum SVR_ID svrId)
{
	char sip[SIP_IP_BUFF_SIZE];
	char dip[SIP_IP_BUFF_SIZE];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;
	char *groupName = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	proto = (char*)server_strfromid(svrId);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);
	if (SVR_ID_SIP == svrId)
	{
		groupName = aclData->groupname;
	}
	else
	{
		groupName = (hdr->svr) ? (hdr->svr->parent_acldata->groupname) : "";
	}

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 17, hdr->udp->source, hdr->udp->dest, proto,
		aclData->user, "none", l_critical, groupName, "false", packLen, content);
}

/************************************************************
*Function    : sip_deletePort
*Action      : delete service mapping information
*Input       : svr  service mapping information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void sip_deletePort(struct server *svr)
{
	unsigned short index;

	for (index = 0; index < g_sipDynamicPortNum; index++)
	{
		if (g_sipDynamicPort[index].isUsed)
		{
			if (g_sipDynamicPort[index].svr == svr)
			{
				g_sipDynamicPort[index].svr = NULL;
				g_sipDynamicPort[index].isUsed = PARSER_BFALSE;
			}
		}
	}
	return;
}

/************************************************************
*Function    : sip_unsetAllSessionSvr
*Action      : remove routes information from session
*Input       : hdr      packet processing header information
			   routes   routes information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void sip_unsetAllSessionSvr(struct filter_header *hdr, SIP_NEW_ROUTE *routes)
{
	SIP_NEW_ROUTE *sipRoute = NULL;

	while (routes)
	{
		sipRoute = routes;
		routes = routes->next;
		if (sipRoute->inUsed)
		{
			hdr->svr_remove_cb(hdr, sipRoute->data_svr);
			sip_deletePort(sipRoute->data_svr);
			sipRoute->inUsed = PARSER_BFALSE;
		}
	}
	return;
}

/************************************************************
*Function    : sip_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET sip_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	SIP_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogError("invalid para, hdr(%p), user(%p), maybe session is closed[%s:%d]", hdr, hdr->user, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		sip_writeSeceventLog(hdr, packLen, content, SVR_ID_SIP);
	}

	session = hdr->user;

	SCLogInfo("on socket close, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);

	if (NULL != session->routes)
	{
		sip_unsetAllSessionSvr(hdr, session->routes);
	}

	sip_freeSession(session);
	hdr->user = NULL;

	return FLTRET_CLOSE;
}

/************************************************************
*Function    : sip_strStartChrCnt
*Action      : find the specified character in a row
*Input       : string   string
			   c        character
			   count    ccurrence times
*Output      : null
*Return      : string   character position
			   NULL     not find character
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static char *sip_strStartChrCnt(char *string, int len, char c, int count)
{
	int cnt;
	int flag;

	cnt = 0;
	flag = 0;
	while (0 < len)
	{
		if (1 == flag)
		{
			if (('\r' != *string) && ('\n' != *string))
			{
				break;
			}
		}

		if (*string == c)
		{
			cnt++;

			if (cnt >= count)
			{
				return string;
			}
		}

		if (('\r' == *string) || ('\n' == *string))
		{
			flag = 1;
		}

		string++;
		len--;
	}

	return NULL;
}

/************************************************************
*Function    : sip_strEndChr
*Action      : find the end character in a row
*Input       : string   string
*Output      : null
*Return      : string   character position
			   NULL     not find character
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static char *sip_strEndChr(char *string, int len)
{
	while (0 < len)
	{
		if ((('0' > *string) || ('9' < *string)) && ('.' != *string) && (':' != *string))
		{
			return string;
		}
		string++;
		len--;
	}

	return NULL;
}

/************************************************************
*Function    : sip_getPort
*Action      : get service mapping information
*Input       : null
*Output      : newPort1     new port
			   newPort2     new port
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int sip_getPort(unsigned short *newPort1, unsigned short *newPort2)
{
	unsigned short index;

	for (index = 0; index < g_sipDynamicPortNum - 1; index++)
	{
		if ((!g_sipDynamicPort[index].isUsed) && (!g_sipDynamicPort[index + 1].isUsed))
		{
			g_sipDynamicPort[index].isUsed = PARSER_BTRUE;
			g_sipDynamicPort[index + 1].isUsed = PARSER_BTRUE;
			*newPort1 = index + g_gapcfg->port_sip_begin;
			*newPort2 = index + 1 + g_gapcfg->port_sip_begin;
			return PARSER_OK;
		}
	}

	return PARSER_ERROR;
}

/************************************************************
*Function    : sip_setPort
*Action      : set service mapping information
*Input       : svr service mapping information
*Output      : null
*Return      : returned new service port    success
			   0                            failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int sip_setPort(unsigned short localPort, struct server *svr)
{
	unsigned short index;

	if ((g_gapcfg->port_sip_begin > localPort) || (g_gapcfg->port_sip_end < localPort))
	{
		SCLogError("invalid port(%u), range[%u, %u][%s:%d]",
			localPort, g_gapcfg->port_sip_begin, g_gapcfg->port_sip_end, __func__, __LINE__);
		return PARSER_ERROR;
	}

	index = localPort - g_gapcfg->port_sip_begin;
	if (!g_sipDynamicPort[index].isUsed)
	{
		SCLogError("localPort(%u) not used[%s:%d]", localPort, __func__, __LINE__);
		return PARSER_ERROR;
	}

	g_sipDynamicPort[index].svr = svr;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_getTag
*Action      : get tag
*Input       : data     data
			   len      data length
*Output      : tag      tag
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.17
*Instruction : null
************************************************************/
static void sip_getTag(char *data, int len, char *tag)
{
	int left;
	int count;
	char *pcursor = NULL;

	pcursor = strnstr(data, "tag=", len);
	if (NULL == pcursor)
	{
		SCLogError("not find tag, data(%s), len(%d)[%s:%d]", data, len, __func__, __LINE__);
		return;
	}

	/* 4:length of "tag=" */
	pcursor += 4;

	count = 0;
	left = len;
	while (0 < left)
	{
		if (SIP_TAG_BUFF_LEN <= count)
		{
			SCLogError("invalid tag, data(%s), len(%d)[%s:%d]", data, len, __func__, __LINE__);
			memset(tag, 0, SIP_TAG_BUFF_LEN);
			break;
		}

		if (('\r' == *pcursor) || ('\n' == *pcursor) || (' ' == *pcursor) || ('\0' == *pcursor))
		{
			break;
		}

		*tag = *pcursor;
		pcursor++;
		tag++;
		count++;
		left--;
	}
	return;
}

/************************************************************
*Function    : sip_delTagRoutes
*Action      : delete tag routes
*Input       : hdr      packet processing header information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.17
*Instruction : null
************************************************************/
static void sip_delTagRoutes(struct filter_header *hdr, char *fromTag, char *toTag)
{
	int len;
	SIP_SESSION *session = NULL;
	SIP_NEW_ROUTE *routes = NULL;
	SIP_NEW_ROUTE *sipRoute = NULL;

	session = hdr->user;
	routes = session->routes;
	while (routes)
	{
		sipRoute = routes;
		routes = routes->next;
		if (sipRoute->inUsed)
		{
			len = strlen(sipRoute->fromTag);
			if (fromTag && (!strncmp(sipRoute->fromTag, fromTag, len)))
			{
				SCLogInfo("delete sipdata route(%s:%u --> %s:%u), svr(%p), sessionid(%u)[%s:%d]",
					sipRoute->data_svr->localip, sipRoute->data_svr->localport,
					sipRoute->data_svr->dstip, sipRoute->data_svr->dstport,
					sipRoute->data_svr, hdr->sessionid, __func__, __LINE__);
				hdr->svr_remove_cb(hdr, sipRoute->data_svr);
				sip_deletePort(sipRoute->data_svr);
				sipRoute->inUsed = PARSER_BFALSE;
			}
			else if (toTag && (!strncmp(sipRoute->fromTag, toTag, len)))
			{
				SCLogInfo("delete sipdata route(%s:%u --> %s:%u), svr(%p), sessionid(%u)[%s:%d]",
					sipRoute->data_svr->localip, sipRoute->data_svr->localport,
					sipRoute->data_svr->dstip, sipRoute->data_svr->dstport,
					sipRoute->data_svr, hdr->sessionid, __func__, __LINE__);
				hdr->svr_remove_cb(hdr, sipRoute->data_svr);
				sip_deletePort(sipRoute->data_svr);
				sipRoute->inUsed = PARSER_BFALSE;
			}
		}
	}
	return;
}

/************************************************************
*Function    : sip_checkContentLength
*Action      : check content length
*Input       : pContentLenAddr   content length start address
*Output      : outContentLen     content length string
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.4
*Instruction : null
************************************************************/
static int sip_checkContentLength(char *pContentLenAddr, int len, char *outContentLen)
{
	int count;

	count = 1;
	while (0 < len)
	{
		if ((0x0d == *pContentLenAddr) || (0x0a == *pContentLenAddr))
		{
			*outContentLen = '\0';
			break;
		}

		if ((SIP_CONTENT_LEN_MAX_BITS < count) || ('9' < *pContentLenAddr) || ('0' > *pContentLenAddr))
		{
			SCLogError("invalid content length[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		*outContentLen = *pContentLenAddr;
		outContentLen++;
		pContentLenAddr++;
		count++;
		len--;
	}

	if (0 == len)
	{
		*outContentLen = '\0';
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_getBodyLen
*Action      : get body length
*Input       : data         data
			   len          data length
*Output      : bodyLen      body length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
			   PARSER_CONTINUE   continue
*Author      : liuzongquan(000932)
*Date        : 2017.1.4
*Instruction : null
************************************************************/
static int sip_getBodyLen(char *data, int len, int *bodyLen)
{
	int offset;
	char *pContentLenAddr = NULL;
	char contentLengthArr[SIP_CONTENT_LEN_MAX_BITS + 1];

	pContentLenAddr = strnstr(data, g_headerLunch[SIP_CONTENT_LENGTH].name, len);
	if (NULL == pContentLenAddr)
	{
		/* not find this subject */
		*bodyLen = 0;
		return PARSER_CONTINUE;
	}

	pContentLenAddr += g_headerLunch[SIP_CONTENT_LENGTH].len;
	offset = (int)(pContentLenAddr - data);
	if (PARSER_OK != sip_checkContentLength(pContentLenAddr, len - offset, contentLengthArr))
	{
		return PARSER_ERROR;
	}

	*bodyLen = atoi(contentLengthArr);
	return PARSER_OK;
}

#if GAP_DESC("check and send to req")
/************************************************************
*Function    : sip_checkReqData
*Action      : check request data
*Input       : hdr      packet processing header information
			   data     data
			   len      data length
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.5
*Instruction : null
************************************************************/
static int sip_checkReqData(struct filter_header *hdr, char *data, int len)
{
	int offset;
	char *pcursor = NULL;
	char fromTag[SIP_TAG_BUFF_LEN];
	char toTag[SIP_TAG_BUFF_LEN];
	char sipStr[SIP_IP_BUFF_SIZE];
	char dipStr[SIP_IP_BUFF_SIZE];
	char lipStr[SIP_IP_BUFF_SIZE];

	IP_NUM_TO_STR(hdr->ip->saddr, sipStr, SIP_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->ip->daddr, dipStr, SIP_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->localip, lipStr, SIP_IP_BUFF_SIZE);

	SCLogInfo("from req, data(%p), len(%d), sip(%s), sport(%u), dip(%s), dport(%u), lip(%s), lport(%u), ssid(%u)[%s:%d]",
		data, len, sipStr, hdr->udp->source, dipStr, hdr->udp->dest,
		lipStr, hdr->localport, hdr->sessionid, __func__, __LINE__);

	if (!strncmp(data, g_methodLunch[SIP_SIP].name, g_methodLunch[SIP_SIP].len))
	{
		/* Status */
		pcursor = sip_strStartChrCnt(data, len, ' ', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid status content, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/*
			status 480: rejected by the other side
			status 404: not find other side
		*/
		if ((NULL == hdr->svr) && ((!strncmp(pcursor + 1, "480", SIP_STATUS_CODE_LEN))
			|| (!strncmp(pcursor + 1, "404", SIP_STATUS_CODE_LEN))))
		{
			SCLogInfo("status(%s), rejected[%s:%d]", "480", __func__, __LINE__);
			pcursor = strnstr(data, g_headerLunch[SIP_FROM].name, len);
			if (NULL == pcursor)
			{
				SCLogError("not find (%s), ssid(%u)[%s:%d]", g_headerLunch[SIP_FROM].name, hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			offset = (int)(pcursor - data);
			sip_getTag(pcursor, len - offset, fromTag);
			sip_delTagRoutes(hdr, fromTag, NULL);
		}
	}
	else if (!strncmp(data, g_methodLunch[SIP_BYE].name, g_methodLunch[SIP_BYE].len))
	{
		SCLogInfo("method(%s), hung up[%s:%d]", g_methodLunch[SIP_BYE].name, __func__, __LINE__);

		/* get fromTag */
		pcursor = strnstr(data, g_headerLunch[SIP_FROM].name, len);
		if (NULL == pcursor)
		{
			SCLogError("not find (%s), ssid(%u)[%s:%d]", g_headerLunch[SIP_FROM].name, hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
		offset = (int)(pcursor - data);
		sip_getTag(pcursor, len - offset, fromTag);

		/* get toTag */
		pcursor = strnstr(data, g_headerLunch[SIP_TO].name, len);
		if (NULL == pcursor)
		{
			SCLogError("not find (%s), ssid(%u)[%s:%d]", g_headerLunch[SIP_TO].name, hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
		offset = (int)(pcursor - data);
		sip_getTag(pcursor, len - offset, toTag);
		sip_delTagRoutes(hdr, fromTag, toTag);
	}

	return PARSER_OK;
}

#endif

#if GAP_DESC("client request message")

/************************************************************
*Function    : sip_checkCltEventReqbufData
*Action      : check the full session in reqbuf
*Input       : hdr          packet processing header information
			   evnetBuf     event buffer
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int sip_checkCltEventReqbufData(struct filter_header *hdr, struct evbuffer *evnetBuf)
{
	int result;
	int bodyLen;
	ev_ssize_t ret;
	size_t eventBufLen;
	struct evbuffer_ptr pos;
	char data[SIP_BUFF_DATA_LEN];

	while (1)
	{
		/* Get data length of client request eventbuffer */
		eventBufLen = evbuffer_get_length(evnetBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check head data all receive */
		pos = evbuffer_search(evnetBuf, "\r\n\r\n", 4, NULL);
		if (-1 == pos.pos)
		{
			break;
		}

		/* Get header */
		ret = evbuffer_copyout(evnetBuf, data, pos.pos + 4);
		if (-1 == ret)
		{
			SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body length */
		result = sip_getBodyLen(data, (int)(pos.pos) + 4, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			if (0 != evbuffer_drain(evnetBuf, pos.pos + 4))
			{
				SCLogError("drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			continue;
		}

		/* Check body data all receive */
		if (eventBufLen < (pos.pos + 4 + (size_t)bodyLen))
		{
			break;
		}

		/* Delete header */
		if (0 != evbuffer_drain(evnetBuf, pos.pos + 4))
		{
			SCLogError("drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body to cache */
		if (0 < bodyLen)
		{
			ret = evbuffer_remove(evnetBuf, data + (int)(pos.pos) + 4, bodyLen);
			if (-1 == ret)
			{
				SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		/* Check */
		result = sip_checkReqData(hdr, data, (pos.pos + 4 + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_checkCltReqbufData
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
static int sip_checkCltReqbufData(struct filter_header *hdr, struct evbuffer *evnetBuf, char *buff, int len)
{
	int result;
	int offset;
	int bodyLen;
	char *pos = NULL;

	while (1)
	{
		/* Get data length of request buff */
		if (0 >= len)
		{
			break;
		}

		/* Check head data all receive */
		pos = strnstr(buff, "\r\n\r\n", len);
		if (NULL == pos)
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Get body data length */
		offset = (int)(pos - buff) + 4;
		result = sip_getBodyLen(buff, offset, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			buff = pos + 4;
			len -= offset;
			continue;
		}

		/* Check body data all receive */
		if (len < (offset + bodyLen))
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Check */
		result = sip_checkReqData(hdr, buff, (offset + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}

		buff = pos + 4 + bodyLen;
		len -= (offset + bodyLen);
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_handleClientReq
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
static int sip_handleClientReq(struct filter_header *hdr, SIP_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Client handle: req buffer and this data */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("add data to session req buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			if (PARSER_OK != sip_checkCltEventReqbufData(hdr, session->reqBuf))
			{
				return PARSER_ERROR;
			}
		}
	}
	else
	{
		/* Client handle: this data */
		if ((NULL != buff) && (0 < len))
		{
			if (PARSER_OK != sip_checkCltReqbufData(hdr, session->reqBuf, (char *)buff, (int)len))
			{
				return PARSER_ERROR;
			}
		}
	}

	if ((NULL != buff) && (0 < len))
	{
		/* Send this data */
		SCLogInfo("send to fwd, len(%u), ssid(%u)[%s:%d]\n", (unsigned int)len, hdr->sessionid, __func__, __LINE__);
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
*Function    : sip_checkSvrEventReqbufData
*Action      : check the full session in reqbuf
*Input       : hdr          packet processing header information
			   evnetBuf     event buffer
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int sip_checkSvrEventReqbufData(struct filter_header *hdr, struct evbuffer *evnetBuf)
{
	int result;
	int bodyLen;
	ev_ssize_t ret;
	size_t eventBufLen;
	struct evbuffer_ptr pos;
	char data[SIP_BUFF_DATA_LEN];

	while (1)
	{
		/* Get data length of client request eventbuffer */
		eventBufLen = evbuffer_get_length(evnetBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check head data all receive */
		pos = evbuffer_search(evnetBuf, "\r\n\r\n", 4, NULL);
		if (-1 == pos.pos)
		{
			break;
		}

		/* Get header */
		ret = evbuffer_copyout(evnetBuf, data, pos.pos + 4);
		if (-1 == ret)
		{
			SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body length */
		result = sip_getBodyLen(data, (int)(pos.pos) + 4, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			if (0 != evbuffer_drain(evnetBuf, pos.pos + 4))
			{
				SCLogError("drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			continue;
		}

		/* Check body data all receive */
		if (eventBufLen < (pos.pos + 4 + (size_t)bodyLen))
		{
			break;
		}

		/* Delete header */
		if (0 != evbuffer_drain(evnetBuf, pos.pos + 4))
		{
			SCLogError("drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body to cache */
		if (0 < bodyLen)
		{
			ret = evbuffer_remove(evnetBuf, data + (int)(pos.pos) + 4, bodyLen);
			if (-1 == ret)
			{
				SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		/* Check */
		result = sip_checkReqData(hdr, data, (pos.pos + 4 + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_checkSvrReqbufData
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
static int sip_checkSvrReqbufData(struct filter_header *hdr, struct evbuffer *evnetBuf, char *buff, int len)
{
	int result;
	int offset;
	int bodyLen;
	char *pos = NULL;

	while (1)
	{
		/* Get data length of request buff */
		if (0 >= len)
		{
			break;
		}

		/* Check head data all receive */
		pos = strnstr(buff, "\r\n\r\n", len);
		if (NULL == pos)
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Get body data length */
		offset = (int)(pos - buff) + 4;
		result = sip_getBodyLen(buff, offset, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			buff = pos + 4;
			len -= offset;
			continue;
		}

		/* Check body data all receive */
		if (len < (offset + bodyLen))
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Check */
		result = sip_checkReqData(hdr, buff, (offset + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}

		buff = pos + 4 + bodyLen;
		len -= (offset + bodyLen);
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_handleServerReq
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
static int sip_handleServerReq(struct filter_header *hdr, SIP_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Server handle: req buffer and this data */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("add data to session req buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			if (PARSER_OK != sip_checkSvrEventReqbufData(hdr, session->reqBuf))
			{
				return PARSER_ERROR;
			}
		}
	}
	else
	{
		/* Server handle: this data */
		if ((NULL != buff) && (0 < len))
		{
			if (PARSER_OK != sip_checkSvrReqbufData(hdr, session->reqBuf, (char *)buff, (int)len))
			{
				return PARSER_ERROR;
			}
		}
	}

	if ((NULL != buff) && (0 < len))
	{
		/* Send this data */
		SCLogInfo("send to fwd, len(%u), ssid(%u)[%s:%d]\n", (unsigned int)len, hdr->sessionid, __func__, __LINE__);
		if (0 != buffer_sendtofwd(hdr, buff, len))
		{
			SCLogError("send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}
#endif

/************************************************************
*Function    : sip_getCseqType
*Action      : get cseq info
*Input       : data     data
			   len      data length
*Output      : cseqType     cseqType
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.11
*Instruction : null
************************************************************/
static int sip_getCseqType(char *data, int len, char *cseqType)
{
	char count;
	char *pcursor = NULL;

	pcursor = strnstr(data, g_headerLunch[SIP_CSEQ].name, len);
	if (NULL == pcursor)
	{
		return PARSER_ERROR;
	}

	pcursor += g_headerLunch[SIP_CSEQ].len;
	len -= g_headerLunch[SIP_CSEQ].len;

	count = 0;
	while (0 < len)
	{
		if (count >= SIP_CSEQ_BUFF_LEN)
		{
			SCLogError("invalid cseq, count(%d), max(%d)[%s:%d]", count, SIP_CSEQ_BUFF_LEN, __func__, __LINE__);
			return PARSER_ERROR;
		}

		if (('\r' == *pcursor) || ('\n' == *pcursor))
		{
			*cseqType = '\0';
			break;
		}

		*cseqType = *pcursor;
		pcursor++;
		cseqType++;
		len--;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_writeLine
*Action      : wirte one line
*Input       : pwrite   write position
			   pread    read position
*Output      : newLen   new data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static void sip_writeLine(char **pwrite, char **pread, int *readLen, int *newLen)
{
	char flag;

	flag = 0;
	while (0 < *readLen)
	{
		if (0 == flag)
		{
			if (('\r' == **pread) || ('\n' == **pread))
			{
				flag = 1;
			}

			**pwrite = **pread;
			(*newLen)++;
			(*pwrite)++;
			(*pread)++;
			(*readLen)--;
		}
		else
		{
			if (('\r' != **pread) && ('\n' != **pread))
			{
				break;
			}
			else
			{
				**pwrite = **pread;
				(*newLen)++;
				(*pwrite)++;
				(*pread)++;
				(*readLen)--;
			}
		}
	}

	return;
}

static int sip_getViaOldIpPort(char *data, int len, char *oldIp, char *oldPort)
{
	int index;
	int offset;
	char *pstart = NULL;
	char *pend = NULL;

	pstart = sip_strStartChrCnt(data, len, ' ', 2);
	if (NULL == pstart)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	pstart++;
	offset = (int)(pstart - data);
	pend = sip_strEndChr(pstart, len - offset);
	if (NULL == pend)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	offset = (int)(pend - pstart);
	if ((SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE) <= offset)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	index = 0;
	while (0 < offset)
	{
		if (SIP_IP_BUFF_SIZE <= index)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		if (*pstart == ':')
		{
			oldIp[index] = '\0';
			break;
		}

		oldIp[index] = *pstart;
		index++;
		pstart++;
		offset--;
	}

	if (0 == offset)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	pstart++;
	offset--;
	index = 0;
	while (0 < offset)
	{
		if (SIP_PORT_BUFF_SIZE <= index)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		if ((*pstart == ';') || (*pstart == '\r') || (*pstart == '\n'))
		{
			oldPort[index] = '\0';
			break;
		}

		oldPort[index] = *pstart;
		index++;
		pstart++;
		offset--;
	}
	oldPort[index] = '\0';

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateViaLine
*Action      : update via line
*Input       : ipStr    ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateViaLine(char **pread, int *readLen, char **pwrite, int *newLen, char *ipStr, uint16_t port)
{
	int newIpLen;
	int newPortLen;
	int oldIpLen;
	int oldPortLen;
	char oldIp[SIP_IP_BUFF_SIZE];
	char oldPort[SIP_PORT_BUFF_SIZE];
	char newPort[SIP_PORT_BUFF_SIZE];

	snprintf(newPort, SIP_PORT_BUFF_SIZE, "%u", port);
	newIpLen = strlen(ipStr);
	newPortLen = strlen(newPort);

	/* get old ip and port */
	if (PARSER_OK != sip_getViaOldIpPort(*pread, *readLen, oldIp, oldPort))
	{
		return PARSER_ERROR;
	}

	/* replace ip and port */
	oldIpLen = strlen(oldIp);
	oldPortLen = strlen(oldPort);
	while (0 < *readLen)
	{
		if (('\r' == **pread) || ('\n' == **pread))
		{
			break;
		}

		if (**pread == oldIp[0])
		{
			if (!strncmp(*pread, oldIp, oldIpLen))
			{
				memcpy(*pwrite, ipStr, newIpLen);
				*pwrite += newIpLen;
				*newLen += newIpLen;
				*pread += oldIpLen;
				*readLen -= oldIpLen;
				continue;
			}
		}
		else if (**pread == oldPort[0])
		{
			if (!strncmp(*pread, oldPort, oldPortLen))
			{
				memcpy(*pwrite, newPort, newPortLen);
				*pwrite += newPortLen;
				*newLen += newPortLen;
				*pread += oldPortLen;
				*readLen -= oldPortLen;
				continue;
			}
		}

		**pwrite = **pread;
		(*pwrite)++;
		(*newLen)++;
		(*pread)++;
		(*readLen)--;
	}

	sip_writeLine(pwrite, pread, readLen, newLen);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateContactLine
*Action      : update contact line
*Input       : lipStr   local ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateContactLine(char **pread, int *readLen, char **pwrite, int *newLen,
	char *lipStr, uint16_t lport)
{
	int tmp;
	char *pcursor = NULL;
	char pBuff[SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE];

	pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	tmp = pcursor - *pread + 1;
	strncpy(*pwrite, *pread, tmp);
	*pread += tmp;
	*readLen -= tmp;
	*pwrite += tmp;
	*newLen += tmp;

	snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s:%u", lipStr, lport);
	tmp = strlen(pBuff);
	strncpy(*pwrite, pBuff, tmp);
	*pwrite += tmp;
	*newLen += tmp;

	pcursor = sip_strEndChr(*pread, *readLen);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}
	tmp = (int)(pcursor - *pread);
	*pread = pcursor;
	*readLen -= tmp;

	sip_writeLine(pwrite, pread, readLen, newLen);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateFromLine
*Action      : update from line
*Input       : ipStr    ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateFromLine(char **pread, int *readLen, char **pwrite, int *newLen, char *fromTag, char *ipStr)
{
	int tmp;
	char *pcursor = NULL;

	pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	tmp = pcursor - *pread + 1;
	strncpy(*pwrite, *pread, tmp);
	*pread += tmp;
	*readLen -= tmp;
	*pwrite += tmp;
	*newLen += tmp;

	tmp = strlen(ipStr);
	strncpy(*pwrite, ipStr, tmp);
	*pwrite += tmp;
	*newLen += tmp;

	pcursor = sip_strEndChr(*pread, *readLen);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}
	tmp = (int)(pcursor - *pread);
	*pread = pcursor;
	*readLen -= tmp;

	if (fromTag)
	{
		sip_getTag(*pread, *readLen, fromTag);
	}

	sip_writeLine(pwrite, pread, readLen, newLen);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateOwnerLine
*Action      : update ower line
*Input       : ipStr    ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateOwnerLine(char **pread, int *readLen, char **pwrite, int *newLen, char *ipStr, char *serverIp)
{
	int tmp;
	char *pcursor = NULL;

	pcursor = sip_strStartChrCnt(*pread, *readLen, ' ', 5);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	tmp = pcursor - *pread + 1;
	strncpy(*pwrite, *pread, tmp);
	*pread += tmp;
	*readLen -= tmp;
	*pwrite += tmp;
	*newLen += tmp;

	tmp = strlen(ipStr);
	strncpy(*pwrite, ipStr, tmp);
	*pwrite += tmp;
	*newLen += tmp;

	pcursor = sip_strEndChr(*pread, *readLen);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}
	tmp = (int)(pcursor - *pread);
	if (SIP_IP_BUFF_SIZE <= tmp)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}
	memcpy(serverIp, *pread, tmp);
	*pread = pcursor;
	*readLen -= tmp;

	sip_writeLine(pwrite, pread, readLen, newLen);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateConnectionLine
*Action      : update connection line
*Input       : ipStr    ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateConnectionLine(char **pread, int *readLen, char **pwrite, int *newLen, char *ipStr, char *serverIp)
{
	int tmp;
	char *pcursor = NULL;

	pcursor = sip_strStartChrCnt(*pread, *readLen, ' ', 2);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	tmp = pcursor - *pread + 1;
	strncpy(*pwrite, *pread, tmp);
	*pread += tmp;
	*readLen -= tmp;
	*pwrite += tmp;
	*newLen += tmp;

	tmp = strlen(ipStr);
	strncpy(*pwrite, ipStr, tmp);
	*pwrite += tmp;
	*newLen += tmp;

	pcursor = sip_strEndChr(*pread, *readLen);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}
	tmp = (int)(pcursor - *pread);
	if (SIP_IP_BUFF_SIZE <= tmp)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}
	if (0 == strlen(serverIp))
	{
		memcpy(serverIp, *pread, tmp);
	}
	*pread = pcursor;
	*readLen -= tmp;

	sip_writeLine(pwrite, pread, readLen, newLen);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_setSvrToSession
*Action      : add svr information to session
*Input       : session  session
			   svr      service mapping information
*Output      : null
*Return      : sip route        success
			   NULL             failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static SIP_NEW_ROUTE *sip_setSvrToSession(struct filter_header *hdr, struct server *svr,
	unsigned short newPort1, unsigned short newPort2, char *tag)
{
	SIP_SESSION *session = NULL;
	SIP_NEW_ROUTE *sipRoute = NULL;

	session = hdr->user;
	sipRoute = (SIP_NEW_ROUTE *)SCMalloc(sizeof(SIP_NEW_ROUTE));
	if (NULL == sipRoute)
	{
		SCLogError("SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)sizeof(SIP_NEW_ROUTE), __func__, __LINE__);
		return NULL;
	}

	memcpy(sipRoute->fromTag, tag, SIP_TAG_BUFF_LEN);
	sipRoute->newPortMsg = newPort1;
	sipRoute->newPortReport = newPort2;
	sipRoute->data_svr = svr;
	sipRoute->inUsed = PARSER_BTRUE;
	sipRoute->next = session->routes;
	session->routes = sipRoute;

	return sipRoute;
}

/************************************************************
*Function    : sip_addDataSvr
*Action      : add svr to dynamic port
*Input       : hdr          packet processing header information
			   ipStr        local ip string
			   serverPort   server port
			   newPort1     local new port
			   newPort2     local new port
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.10
*Instruction : null
************************************************************/
static int sip_addDataSvr(struct filter_header *hdr, char *ipStr, char *serverIp, unsigned short serverPort,
	unsigned short newPort1, unsigned short newPort2, char *tag)
{
	struct server *mgrSvr = NULL;
	struct server *dataSvr = NULL;
	SIP_NEW_ROUTE *sipRoute = NULL;

	if (ROUTE_MAPPED == hdr->routetype)
	{
		mgrSvr = server_new(SVR_ID_SIPDATA, "sipdata server", ipStr, newPort1, serverIp, serverPort);
	}
	else
	{
		mgrSvr = server_new(SVR_ID_SIPDATA, "sipdata server", ipStr, 0, serverIp, serverPort);
	}
	if (mgrSvr == NULL)
	{
		SCLogError("server_new memory failed, size(%u), sessionid(%u)[%s:%d]",
			(unsigned int)sizeof(struct server), hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (PARSER_OK != sip_setPort(newPort1, mgrSvr))
	{
		sip_deletePort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;
		return PARSER_ERROR;
	}

	hdr->svr_add_cb(hdr, mgrSvr);
	sipRoute = sip_setSvrToSession(hdr, mgrSvr, newPort1, newPort2, tag);
	if (NULL == sipRoute)
	{
		hdr->svr_remove_cb(hdr, mgrSvr);
		sip_deletePort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;
	}
	SCLogInfo("add sipdata route(%s:%u --> %s:%u), svr(%p), sessionid(%u)[%s:%d]",
		ipStr, (ROUTE_MAPPED == hdr->routetype) ? newPort1 : 0, serverIp,
		serverPort, mgrSvr, hdr->sessionid, __func__, __LINE__);

	if (ROUTE_MAPPED == hdr->routetype)
	{
		dataSvr = server_new(SVR_ID_SIPDATA, "sipdata server", ipStr, newPort2, serverIp, serverPort + 1);
	}
	else
	{
		dataSvr = server_new(SVR_ID_SIPDATA, "sipdata server", ipStr, 0, serverIp, serverPort + 1);
	}
	if (dataSvr == NULL)
	{
		SCLogError("server_new memory failed, size(%u), sessionid(%u)[%s:%d]",
			(unsigned int)sizeof(struct server), hdr->sessionid, __func__, __LINE__);
		sipRoute->inUsed = PARSER_BFALSE;
		hdr->svr_remove_cb(hdr, mgrSvr);
		sip_deletePort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;
		return PARSER_ERROR;
	}

	if (PARSER_OK != sip_setPort(newPort2, dataSvr))
	{
		sipRoute->inUsed = PARSER_BFALSE;
		hdr->svr_remove_cb(hdr, mgrSvr);
		sip_deletePort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;

		sip_deletePort(dataSvr);
		server_free(dataSvr);
		dataSvr = NULL;
		return PARSER_ERROR;
	}

	hdr->svr_add_cb(hdr, dataSvr);
	if (NULL == sip_setSvrToSession(hdr, dataSvr, newPort1, newPort2, tag))
	{
		sipRoute->inUsed = PARSER_BFALSE;
		hdr->svr_remove_cb(hdr, mgrSvr);
		sip_deletePort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;

		hdr->svr_remove_cb(hdr, dataSvr);
		sip_deletePort(dataSvr);
		server_free(dataSvr);
		dataSvr = NULL;
	}
	SCLogInfo("add sipdata route(%s:%u --> %s:%u), svr(%p), sessionid(%u)[%s:%d]",
		ipStr, (ROUTE_MAPPED == hdr->routetype) ? newPort2 : 0, serverIp,
		serverPort + 1, dataSvr, hdr->sessionid, __func__, __LINE__);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_isTagExist
*Action      : check tag
*Input       : hdr          packet processing header information
			   tag      from tag
*Output      : dynamicPort  dynamic port
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.17
*Instruction : null
************************************************************/
static char sip_isTagExist(struct filter_header *hdr, char *tag, char *dynamicPort)
{
	SIP_SESSION *session = NULL;
	SIP_NEW_ROUTE *routes = NULL;
	SIP_NEW_ROUTE *sipRoute = NULL;

	session = hdr->user;
	routes = session->routes;
	while (routes)
	{
		sipRoute = routes;
		routes = routes->next;
		if (!strncmp(sipRoute->fromTag, tag, SIP_TAG_BUFF_LEN))
		{
			snprintf(dynamicPort, SIP_PORT_BUFF_SIZE, "%u", sipRoute->newPortMsg);
			return PARSER_BTRUE;
		}
	}

	return PARSER_BFALSE;
}

/************************************************************
*Function    : sip_createDataSvr
*Action      : get port and add svr
*Input       : hdr          packet processing header information
			   ipStr        local ip string
			   data         data
*Output      : dynamicPort  dynamic port
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.10
*Instruction : null
************************************************************/
static int sip_createDataSvr(struct filter_header *hdr, char *ipStr, char *serverIp,
	char *data, int len, char *tag, char *dynamicPort)
{
	int offset;
	unsigned short newPort1;
	unsigned short newPort2;
	unsigned short serverPort;
	char *pcursor = NULL;
	char serverPortStr[SIP_PORT_BUFF_SIZE];

	if (0 == strlen(tag))
	{
		SCLogError("invalid tag, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	/* Check port is present */
	if (sip_isTagExist(hdr, tag, dynamicPort))
	{
		return PARSER_OK;
	}

	/* Get server port */
	pcursor = sip_strEndChr(data, len);
	if (NULL == pcursor)
	{
		SCLogError("invalid content, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	offset = (int)(pcursor - data);
	if (offset >= SIP_PORT_BUFF_SIZE)
	{
		SCLogError("invalid content, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	memset(serverPortStr, 0, SIP_PORT_BUFF_SIZE);
	strncpy(serverPortStr, data, offset);
	serverPort = (unsigned short)atoi(serverPortStr);

	/* Get new port */
	if (PARSER_OK != sip_getPort(&newPort1, &newPort2))
	{
		SCLogError("can't find valid sip port, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}
	snprintf(dynamicPort, SIP_PORT_BUFF_SIZE, "%u", newPort1);

	/* Add data svr */
	if (PARSER_OK != sip_addDataSvr(hdr, ipStr, serverIp, serverPort, newPort1, newPort2, tag))
	{
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateMediaLine
*Action      : update media line
*Input       : hdr      packet processing header information
			   ipStr    ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateMediaLine(struct filter_header *hdr, SIP_BODY_SUBJECT_ID bodySubject,
	char **pread, int *readLen, char **pwrite, int *newLen,
	char *ipStr, char *serverIp, char *tag)
{
	int tmp;
	int offset;
	char *pcursor = NULL;
	char dynamicPort[SIP_PORT_BUFF_SIZE];

	if (0 == strlen(serverIp))
	{
		SCLogError("invalid server ip(null)[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	switch (bodySubject)
	{
	case SIP_MEDIA_AUDIO:
	case SIP_MEDIA_VIDEO:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, ' ', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Create data svr */
		offset = (int)(pcursor - *pread) + 1;
		if (PARSER_OK != sip_createDataSvr(hdr, ipStr, serverIp, pcursor + 1, *readLen - offset, tag, dynamicPort))
		{
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		if (ROUTE_MAPPED == hdr->routetype)
		{
			tmp = strlen(dynamicPort);
			strncpy(*pwrite, dynamicPort, tmp);
			*pwrite += tmp;
			*newLen += tmp;

			pcursor = sip_strEndChr(*pread, *readLen);
			if (NULL == pcursor)
			{
				SCLogError("invalid content[%s:%d]", __func__, __LINE__);
				return PARSER_ERROR;
			}
			tmp = (int)(pcursor - *pread);
			*pread = pcursor;
			*readLen -= tmp;
		}
		break;
	}

	case SIP_MEDIA_ALT:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, ' ', 5);
		if (NULL == pcursor)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		if ((ROUTE_MAPPED == hdr->routetype) && (!strncmp(*pread, serverIp, strlen(serverIp))))
		{
			tmp = strlen(ipStr);
			strncpy(*pwrite, ipStr, tmp);
			*pwrite += tmp;
			*newLen += tmp;
			**pwrite = ' ';
			*pwrite += 1;
			*newLen += 1;
			pcursor = sip_strEndChr(*pread, *readLen);
			if (NULL == pcursor)
			{
				SCLogError("invalid content[%s:%d]", __func__, __LINE__);
				return PARSER_ERROR;
			}
			tmp = (int)(pcursor - *pread) + 1;
			*pread = pcursor + 1;
			*readLen -= tmp;
		}
		else
		{
			pcursor = sip_strEndChr(*pread, *readLen);
			if (NULL == pcursor)
			{
				SCLogError("invalid content[%s:%d]", __func__, __LINE__);
				return PARSER_ERROR;
			}
			tmp = (int)(pcursor - *pread) + 1;
			strncpy(*pwrite, *pread, tmp);
			*pwrite += tmp;
			*newLen += tmp;
			**pwrite = ' ';
			*pwrite += 1;
			*newLen += 1;
			*pread = pcursor + 1;
			*readLen -= tmp;
		}

		/* Create data svr */
		if (PARSER_OK != sip_createDataSvr(hdr, ipStr, serverIp, *pread, *readLen, tag, dynamicPort))
		{
			return PARSER_ERROR;
		}

		if (ROUTE_MAPPED == hdr->routetype)
		{
			tmp = strlen(dynamicPort);
			strncpy(*pwrite, dynamicPort, tmp);
			*pwrite += tmp;
			*newLen += tmp;

			pcursor = sip_strEndChr(*pread, *readLen);
			if (NULL == pcursor)
			{
				SCLogError("invalid content[%s:%d]", __func__, __LINE__);
				return PARSER_ERROR;
			}
			tmp = (int)(pcursor - *pread);
			*pread = pcursor;
			*readLen -= tmp;
		}
		break;
	}

	default:
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		break;
	}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateToLine
*Action      : update to line
*Input       : ipStr    ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateToLine(char **pread, int *readLen, char **pwrite, int *newLen, char *toTag, char *ipStr)
{
	int tmp;
	char *pcursor = NULL;

	pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}

	tmp = pcursor - *pread + 1;
	strncpy(*pwrite, *pread, tmp);
	*pread += tmp;
	*readLen -= tmp;
	*pwrite += tmp;
	*newLen += tmp;

	tmp = strlen(ipStr);
	strncpy(*pwrite, ipStr, tmp);
	*pwrite += tmp;
	*newLen += tmp;

	pcursor = sip_strEndChr(*pread, *readLen);
	if (NULL == pcursor)
	{
		SCLogError("invalid content[%s:%d]", __func__, __LINE__);
		return PARSER_ERROR;
	}
	tmp = (int)(pcursor - *pread);
	*pread = pcursor;
	*readLen -= tmp;

	if (toTag)
	{
		sip_getTag(*pread, *readLen, toTag);
	}

	sip_writeLine(pwrite, pread, readLen, newLen);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateRLine
*Action      : update R line
*Input       : lipStr   lip string
			   dipStr   dip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.12
*Instruction : null
************************************************************/
static int sip_updateRLine(struct filter_header *hdr, SIP_HEADER_SUBJECT_ID subject, char **pread, int *readLen,
	char **pwrite, int *newLen, char *lipStr, char *dipStr)
{
	int tmp;
	char *pcursor = NULL;
	char pBuff[SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE];

	switch (subject)
	{
	case SIP_ROUTE:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, ':', 2);
		if (NULL == pcursor)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s:%u", dipStr, hdr->udp->dest);
		tmp = strlen(pBuff);
		strncpy(*pwrite, pBuff, tmp);
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	case SIP_RECORD_ROUTE:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, ':', 2);
		if (NULL == pcursor)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		if (hdr->svr)
		{
			//snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s:%u", lipStr, hdr->localport);
			snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s", lipStr);
			tmp = strlen(pBuff);
			strncpy(*pwrite, pBuff, tmp);
		}
		else
		{
			snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s:%u", dipStr, hdr->udp->dest);
			tmp = strlen(pBuff);
			strncpy(*pwrite, pBuff, tmp);
		}
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid content[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	default:
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		break;
	}
	}

	return PARSER_OK;
}

static void sip_updateContentLength(char *content, int *contentLen)
{
	int len;
	int offset;
	int oldLen;
	int newLen;
	char *pHeadEnd = NULL;
	char *pContentLengthEnd = NULL;
	char *pContentLengthStart = NULL;
	char contentLength[SIP_CONTENT_LEN_MAX_BITS + 1];

	len = *contentLen;
	pHeadEnd = strnstr(content, "\r\n\r\n", len);
	if (NULL == pHeadEnd)
	{
		return;
	}

	offset = (int)(pHeadEnd - content) + 4;
	if (len <= offset)
	{
		return;
	}
	snprintf(contentLength, SIP_CONTENT_LEN_MAX_BITS + 1, "%d", (int)(len - offset));
	newLen = strlen(contentLength);

	pContentLengthStart = strnstr(content, "Content-Length: ", len);
	if (NULL == pContentLengthStart)
	{
		SCLogWarning("not find key of Content-Length[%s:%d]", __func__, __LINE__);
		return;
	}

	pContentLengthStart += 16;
	pContentLengthEnd = strchr(pContentLengthStart, '\r');
	if (NULL == pContentLengthEnd)
	{
		pContentLengthEnd = strchr(pContentLengthStart, '\n');
	}

	if (NULL == pContentLengthEnd)
	{
		SCLogError("not find end flag of Content-Length[%s:%d]", __func__, __LINE__);
		return;
	}

	oldLen = (int)(pContentLengthEnd - pContentLengthStart);
	if (SIP_CONTENT_LEN_MAX_BITS < oldLen)
	{
		SCLogError("invalid old length(%d)[%s:%d]", oldLen, __func__, __LINE__);
		return;
	}

	if (newLen == oldLen)
	{
		memcpy(pContentLengthStart, contentLength, newLen);
		return;
	}

	offset = len - (int)(pContentLengthEnd - content);
	if (newLen < oldLen)
	{
		memcpy(pContentLengthStart, contentLength, newLen);
		memcpy(pContentLengthStart + newLen, pContentLengthEnd, offset);
		offset = oldLen - newLen;
		(*contentLen) -= offset;
	}
	else
	{
		memmove(pContentLengthStart + newLen, pContentLengthEnd, offset);
		memcpy(pContentLengthStart, contentLength, newLen);
		offset = newLen - oldLen;
		(*contentLen) += offset;
	}

	return;
}

#if GAP_DESC("update and send to req")
static int sip_handleStatusViaLine(struct filter_header *hdr, char *sipStr, char *dipStr,
	char **pread, int *readLen, char **pwrite, int *newLen)
{
	if (strncmp(*pread, g_headerLunch[SIP_VIA].name, g_headerLunch[SIP_VIA].len))
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		return PARSER_CONTINUE;
	}

	if (hdr->svr)
	{
		SCLogInfo("Via, ip(%s), port(%u)[%s:%d]", sipStr, hdr->udp->source, __func__, __LINE__);
		if (PARSER_OK != sip_updateViaLine(pread, readLen, pwrite, newLen, sipStr, hdr->udp->source))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		SCLogInfo("Via, ip(%s), port(%u)[%s:%d]", dipStr, hdr->udp->dest, __func__, __LINE__);
		if (PARSER_OK != sip_updateViaLine(pread, readLen, pwrite, newLen, dipStr, hdr->udp->dest))
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

static int sip_handleMethodViaLine(struct filter_header *hdr, char *lipStr,
	char **pread, int *readLen, char **pwrite, int *newLen)
{
	if (strncmp(*pread, g_headerLunch[SIP_VIA].name, g_headerLunch[SIP_VIA].len))
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		return PARSER_CONTINUE;
	}

	SCLogInfo("Via, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
	if (PARSER_OK != sip_updateViaLine(pread, readLen, pwrite, newLen, lipStr, hdr->localport))
	{
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

static int sip_handleFromLine(struct filter_header *hdr, char *fromTag, char *lipStr, char *dipStr,
	char **pread, int *readLen, char **pwrite, int *newLen)
{
	if (strncmp(*pread, g_headerLunch[SIP_FROM].name, g_headerLunch[SIP_FROM].len))
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		return PARSER_CONTINUE;
	}

	if (hdr->svr)
	{
		SCLogInfo("From, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
		if (PARSER_OK != sip_updateFromLine(pread, readLen, pwrite, newLen, fromTag, lipStr))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		SCLogInfo("From, ip(%s)[%s:%d]", dipStr, __func__, __LINE__);
		if (PARSER_OK != sip_updateFromLine(pread, readLen, pwrite, newLen, fromTag, dipStr))
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

static int sip_handleToLine(struct filter_header *hdr, char *toTag, char *lipStr, char *dipStr,
	char **pread, int *readLen, char **pwrite, int *newLen)
{
	if (strncmp(*pread, g_headerLunch[SIP_TO].name, g_headerLunch[SIP_TO].len))
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		return PARSER_CONTINUE;
	}

	if (hdr->svr)
	{
		SCLogInfo("To, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
		if (PARSER_OK != sip_updateToLine(pread, readLen, pwrite, newLen, toTag, lipStr))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		SCLogInfo("To, ip(%s)[%s:%d]", dipStr, __func__, __LINE__);
		if (PARSER_OK != sip_updateToLine(pread, readLen, pwrite, newLen, toTag, dipStr))
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

static int sip_handleRouteLine(struct filter_header *hdr, char *lipStr, char *dipStr,
	char **pread, int *readLen, char **pwrite, int *newLen)
{
	if ((strncmp(*pread, g_headerLunch[SIP_ROUTE].name, g_headerLunch[SIP_ROUTE].len))
		&& (strncmp(*pread, g_headerLunch[SIP_RECORD_ROUTE].name, g_headerLunch[SIP_RECORD_ROUTE].len)))
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		return PARSER_CONTINUE;
	}

	SCLogInfo("Route or Record-Route, lip(%s), dip(%s)[%s:%d]", lipStr, dipStr, __func__, __LINE__);
	if ('o' == *((*pread) + 1))
	{
		if (PARSER_OK != sip_updateRLine(hdr, SIP_ROUTE, pread, readLen, pwrite, newLen, lipStr, dipStr))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		if (PARSER_OK != sip_updateRLine(hdr, SIP_RECORD_ROUTE, pread, readLen, pwrite, newLen, lipStr, dipStr))
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_update1xxIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_update1xxIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr, char *cseqType)
{
	int ret;
	int newLen;
	int readLen;
	char viaCnt;
	char method;
	char *pread = NULL;
	char *pwrite = NULL;

	method = SIP_SIP;
	if (strstr(cseqType, g_methodLunch[SIP_INVITE].name))
	{
		method = SIP_INVITE;
	}

	if (SIP_SIP == method)
	{
		*contentLen = len;
		strncpy(content, data, len);
		return PARSER_OK;
	}

	viaCnt = 0;
	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	while (0 < readLen)
	{
		/* c<->s */
		switch (*pread)
		{
		case 'V':
		{
			if (viaCnt)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleStatusViaLine(hdr, sipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}

			viaCnt = 1;
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'C':
		{
			if (strncmp(pread, g_headerLunch[SIP_CONTACT].name, g_headerLunch[SIP_CONTACT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (NULL == hdr->svr)
			{
				SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
				if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			}
			break;
		}

		case 'R':
		{
			ret = sip_handleRouteLine(hdr, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_update2xxIpPort
*Action      : update ip and port
*Input       : hdr      packet processing header information
			   data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_update2xxIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr, char *cseqType)
{
	int ret;
	int newLen;
	int readLen;
	char viaCnt;
	char method;
	char *pread = NULL;
	char *pwrite = NULL;
	char fromTag[SIP_TAG_BUFF_LEN];
	char serverIp[SIP_IP_BUFF_SIZE];

	method = SIP_SIP;
	if (strstr(cseqType, g_methodLunch[SIP_REGISTER].name))
	{
		method = SIP_REGISTER;
	}
	else if (strstr(cseqType, g_methodLunch[SIP_INVITE].name))
	{
		method = SIP_INVITE;
	}
	else if (strstr(cseqType, g_methodLunch[SIP_BYE].name))
	{
		method = SIP_BYE;
	}
	else if (strstr(cseqType, g_methodLunch[SIP_CANCEL].name))
	{
		method = SIP_CANCEL;
	}

	if (SIP_SIP == method)
	{
		*contentLen = len;
		strncpy(content, data, len);
		return PARSER_OK;
	}

	viaCnt = 0;
	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	memset(fromTag, 0, SIP_TAG_BUFF_LEN);
	memset(serverIp, 0, SIP_IP_BUFF_SIZE);
	while (0 < readLen)
	{
		/* c<->s */
		switch (*pread)
		{
		case 'V':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || (viaCnt))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleStatusViaLine(hdr, sipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}

			viaCnt = 1;
			break;
		}

		case 'C':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || strncmp(pread, g_headerLunch[SIP_CONTACT].name, g_headerLunch[SIP_CONTACT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if ((SIP_REGISTER != method) && (SIP_CANCEL != method) && (SIP_INVITE != method))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (NULL == hdr->svr)
			{
				SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
				if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				if (SIP_REGISTER == method)
				{
					SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", sipStr, hdr->udp->source, __func__, __LINE__);
					if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, sipStr, hdr->udp->source))
					{
						return PARSER_ERROR;
					}
				}
				else
				{
					sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				}
			}
			break;
		}

		case 'F':
		{
			if (ROUTE_MAPPED != hdr->routetype)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleFromLine(hdr, fromTag, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			if (ROUTE_MAPPED != hdr->routetype)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'R':
		{
			if (ROUTE_MAPPED != hdr->routetype)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleRouteLine(hdr, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'o':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || strncmp(pread, g_bodyLunch[SIP_OWNER].name, g_bodyLunch[SIP_OWNER].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Ower, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateOwnerLine(&pread, &readLen, &pwrite, &newLen, lipStr, serverIp))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'c':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || strncmp(pread, g_bodyLunch[SIP_CONNECTION].name, g_bodyLunch[SIP_CONNECTION].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Connection, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateConnectionLine(&pread, &readLen, &pwrite, &newLen, lipStr, serverIp))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'm':
		{
			if ((strncmp(pread, g_bodyLunch[SIP_MEDIA_AUDIO].name, g_bodyLunch[SIP_MEDIA_AUDIO].len))
				&& (strncmp(pread, g_bodyLunch[SIP_MEDIA_VIDEO].name, g_bodyLunch[SIP_MEDIA_VIDEO].len)))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("m=audio or m=video, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if ('a' == *(pread + 2))
			{
				if (PARSER_OK != sip_updateMediaLine(hdr, SIP_MEDIA_AUDIO, &pread, &readLen,
					&pwrite, &newLen, lipStr, serverIp, fromTag))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				if (PARSER_OK != sip_updateMediaLine(hdr, SIP_MEDIA_VIDEO, &pread, &readLen,
					&pwrite, &newLen, lipStr, serverIp, fromTag))
				{
					return PARSER_ERROR;
				}
			}
			break;
		}

		case 'a':
		{
			if (strncmp(pread, g_bodyLunch[SIP_MEDIA_ALT].name, g_bodyLunch[SIP_MEDIA_ALT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("a=alt, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateMediaLine(hdr, SIP_MEDIA_ALT, &pread, &readLen,
				&pwrite, &newLen, lipStr, serverIp, fromTag))
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_update4xxIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_update4xxIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr, char *cseqType)
{
	int ret;
	int newLen;
	int readLen;
	char viaCnt;
	char method;
	char *pread = NULL;
	char *pwrite = NULL;

	method = SIP_SIP;
	if (strstr(cseqType, g_methodLunch[SIP_REGISTER].name))
	{
		method = SIP_REGISTER;
	}
	else if (strstr(cseqType, g_methodLunch[SIP_INVITE].name))
	{
		method = SIP_INVITE;
	}
	else if (strstr(cseqType, g_methodLunch[SIP_SUBSCRIBE].name))
	{
		method = SIP_SUBSCRIBE;
	}

	if (SIP_SIP == method)
	{
		*contentLen = len;
		strncpy(content, data, len);
		return PARSER_OK;
	}

	viaCnt = 0;
	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	while (0 < readLen)
	{
		/* c<-s */
		switch (*pread)
		{
		case 'V':
		{
			if (viaCnt)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleStatusViaLine(hdr, sipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}

			viaCnt = 1;
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'R':
		{
			ret = sip_handleRouteLine(hdr, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_update5xxIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.5.25
*Instruction : null
************************************************************/
static int sip_update5xxIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr, char *cseq)
{
	int ret;
	int newLen;
	int readLen;
	char viaCnt;
	char method;
	char *pread = NULL;
	char *pwrite = NULL;

	method = SIP_SIP;
	if (strstr(cseq, g_methodLunch[SIP_SUBSCRIBE].name))
	{
		method = SIP_SUBSCRIBE;
	}

	if (SIP_SIP == method)
	{
		*contentLen = len;
		strncpy(content, data, len);
		return PARSER_OK;
	}

	viaCnt = 0;
	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	while (0 < readLen)
	{
		/* c<-s */
		switch (*pread)
		{
		case 'V':
		{
			if (viaCnt)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleStatusViaLine(hdr, sipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}

			viaCnt = 1;
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

static SIP_STATUS_ID sip_getStatusId(char *data, int len)
{
	int offset;
	char *statusPos = NULL;

	statusPos = sip_strStartChrCnt(data, len, ' ', 1);
	if (NULL == statusPos)
	{
		SCLogWarning("invalid status content[%s:%d]", __func__, __LINE__);
		return SIP_STATUS_BUTT;
	}

	statusPos++;
	offset = (int)(statusPos - data);
	if (SIP_STATUS_CODE_LEN > (len - offset))
	{
		SCLogWarning("invalid status content[%s:%d]", __func__, __LINE__);
		return SIP_STATUS_BUTT;
	}

	SCLogInfo("status(%c%c%c)[%s:%d]", *statusPos, *(statusPos + 1), *(statusPos + 2), __func__, __LINE__);

	if (('0' > *(statusPos + 1)) || ('9' < *(statusPos + 1)) || ('0' > *(statusPos + 2)) || ('9' < *(statusPos + 2)))
	{
		SCLogWarning("invalid status content[%s:%d]", __func__, __LINE__);
		return SIP_STATUS_BUTT;
	}

	switch (*statusPos)
	{
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	{
		break;
	}

	default:
	{
		SCLogWarning("invalid status content[%s:%d]", __func__, __LINE__);
		return SIP_STATUS_BUTT;
	}
	}

	return (*statusPos - 48);
}

static void sip_getSessionData(char *data, int len, char *content, int *contentLen)
{
	*contentLen = len;
	strncpy(content, data, len);
}

static int sip_handleStatus(struct filter_header *hdr, char *data, int len,
	char *sipStr, char *dipStr, char *lipStr, char *cseqType)
{
	int ret;
	int contentLen;
	SIP_STATUS_ID statusCode;
	char content[SIP_BUFF_DATA_LEN];

	statusCode = sip_getStatusId(data, len);
	if (SIP_STATUS_BUTT == statusCode)
	{
		if (0 != buffer_sendtoreq(hdr, data, len))
		{
			SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
		return PARSER_OK;
	}

	switch (statusCode)
	{
	case SIP_1XX:
	{
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_update1xxIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr, cseqType);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}
		sip_getSessionData(data, len, content, &contentLen);
		break;
	}

	case SIP_2XX:
	{
		ret = sip_update2xxIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr, cseqType);
		if (PARSER_OK != ret)
		{
			return PARSER_ERROR;
		}
		break;
	}

	case SIP_4XX:
	{
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_update4xxIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr, cseqType);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}
		sip_getSessionData(data, len, content, &contentLen);
		break;
	}

	case SIP_5XX:
	{
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_update5xxIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr, cseqType);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}
		sip_getSessionData(data, len, content, &contentLen);
		break;
	}

	default:
	{
		sip_getSessionData(data, len, content, &contentLen);
	}
	}

	if (ROUTE_MAPPED == hdr->routetype)
	{
		sip_updateContentLength(content, &contentLen);
	}

	SCLogInfo("send to req, len(%d), ssid(%u)[%s:%d]\n", contentLen, hdr->sessionid, __func__, __LINE__);
	if (0 != buffer_sendtoreq(hdr, content, contentLen))
	{
		SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateRequestLine
*Action      : update register line
*Input       : dipStr   dest ip string
*Output      : pwrite   write position
			   pread    read position
			   newLen   new data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateRequestLine(struct filter_header *hdr, SIP_METHOD_ID method, char **pread,
	int *readLen, char **pwrite, int *newLen, char *ipStr, u_short port)
{
	int tmp;
	char *pcursor = NULL;
	char pBuff[SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE];

	switch (method)
	{
	case SIP_REGISTER:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, ':', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		tmp = strlen(ipStr);
		strncpy(*pwrite, ipStr, tmp);
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	case SIP_SUBSCRIBE:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		tmp = strlen(ipStr);
		strncpy(*pwrite, ipStr, tmp);
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	case SIP_INVITE:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		if (0 == port)
		{
			tmp = strlen(ipStr);
			strncpy(*pwrite, ipStr, tmp);
		}
		else
		{
			snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s:%u", ipStr, port);
			tmp = strlen(pBuff);
			strncpy(*pwrite, pBuff, tmp);
		}
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	case SIP_CANCEL:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		if (0 == port)
		{
			tmp = strlen(ipStr);
			strncpy(*pwrite, ipStr, tmp);
		}
		else
		{
			snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s:%u", ipStr, port);
			tmp = strlen(pBuff);
			strncpy(*pwrite, pBuff, tmp);
		}
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	case SIP_ACK:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		if (0 == port)
		{
			tmp = strlen(ipStr);
			strncpy(*pwrite, ipStr, tmp);
		}
		else
		{
			snprintf(pBuff, SIP_IP_BUFF_SIZE + SIP_PORT_BUFF_SIZE, "%s:%u", ipStr, port);
			tmp = strlen(pBuff);
			strncpy(*pwrite, pBuff, tmp);
		}
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	case SIP_BYE:
	{
		pcursor = sip_strStartChrCnt(*pread, *readLen, '@', 1);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}

		tmp = pcursor - *pread + 1;
		strncpy(*pwrite, *pread, tmp);
		*pread += tmp;
		*readLen -= tmp;
		*pwrite += tmp;
		*newLen += tmp;

		tmp = strlen(ipStr);
		strncpy(*pwrite, ipStr, tmp);
		*pwrite += tmp;
		*newLen += tmp;

		pcursor = sip_strEndChr(*pread, *readLen);
		if (NULL == pcursor)
		{
			SCLogError("invalid request line[%s:%d]", __func__, __LINE__);
			return PARSER_ERROR;
		}
		tmp = (int)(pcursor - *pread);
		*pread = pcursor;
		*readLen -= tmp;
		break;
	}

	default:
	{
		sip_writeLine(pwrite, pread, readLen, newLen);
		break;
	}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateRegisterIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateRegisterIpPort(struct filter_header *hdr, char *data, int len,
	char *content, int *contentLen, char *dipStr, char *lipStr)
{
	int ret;
	int newLen;
	int readLen;
	char *pread = NULL;
	char *pwrite = NULL;

	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	while (0 < readLen)
	{
		/* c->s */
		switch (*pread)
		{
		case 'R':
		{
			if (strncmp(pread, g_methodLunch[SIP_REGISTER].name, g_methodLunch[SIP_REGISTER].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Register, ip(%s)[%s:%d]", dipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateRequestLine(hdr, SIP_REGISTER, &pread, &readLen, &pwrite, &newLen, dipStr, 0))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'V':
		{
			ret = sip_handleMethodViaLine(hdr, lipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'C':
		{
			if (strncmp(pread, g_headerLunch[SIP_CONTACT].name, g_headerLunch[SIP_CONTACT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
			if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateSubscribeIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateSubscribeIpPort(struct filter_header *hdr, char *data, int len,
	char *content, int *contentLen, char *dipStr, char *lipStr)
{
	int ret;
	int newLen;
	int readLen;
	char *pread = NULL;
	char *pwrite = NULL;

	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	while (0 < readLen)
	{
		/* c->s */
		switch (*pread)
		{
		case 'S':
		{
			if (strncmp(pread, g_methodLunch[SIP_SUBSCRIBE].name, g_methodLunch[SIP_SUBSCRIBE].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Subscribe, ip(%s)[%s:%d]", dipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateRequestLine(hdr, SIP_SUBSCRIBE, &pread, &readLen, &pwrite, &newLen, dipStr, 0))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'V':
		{
			ret = sip_handleMethodViaLine(hdr, lipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'C':
		{
			if (strncmp(pread, g_headerLunch[SIP_CONTACT].name, g_headerLunch[SIP_CONTACT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
			if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateInviteIpPort
*Action      : update ip and port
*Input       : hdr      packet processing header information
			   data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateInviteIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr)
{
	int ret;
	int viaCnt;
	int newLen;
	int readLen;
	char *pread = NULL;
	char *pwrite = NULL;
	char fromTag[SIP_TAG_BUFF_LEN];
	char serverIp[SIP_IP_BUFF_SIZE];

	viaCnt = 0;
	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	memset(fromTag, 0, SIP_TAG_BUFF_LEN);
	memset(serverIp, 0, SIP_IP_BUFF_SIZE);
	while (0 < readLen)
	{
		/* c<->s */
		switch (*pread)
		{
		case 'I':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || strncmp(pread, g_methodLunch[SIP_INVITE].name, g_methodLunch[SIP_INVITE].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (NULL == hdr->svr)
			{
				if (strnstr(data, g_headerLunch[SIP_ROUTE].name, len))
				{
					sip_writeLine(&pwrite, &pread, &readLen, &newLen);
					break;
				}
			}

			if (hdr->svr)
			{
				SCLogInfo("Invite, ip(%s), port(%u)[%s:%d]", sipStr, hdr->udp->source, __func__, __LINE__);
				if (PARSER_OK != sip_updateRequestLine(hdr, SIP_INVITE, &pread, &readLen,
					&pwrite, &newLen, sipStr, hdr->udp->source))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				SCLogInfo("Invite, ip(%s)[%s:%d]", dipStr, __func__, __LINE__);
				if (PARSER_OK != sip_updateRequestLine(hdr, SIP_INVITE, &pread, &readLen, &pwrite, &newLen, dipStr, 0))
				{
					return PARSER_ERROR;
				}
			}
			break;
		}

		case 'V':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || viaCnt)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleMethodViaLine(hdr, lipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}

			viaCnt = 1;
			break;
		}

		case 'R':
		{
			if (ROUTE_MAPPED != hdr->routetype)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleRouteLine(hdr, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'C':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || strncmp(pread, g_headerLunch[SIP_CONTACT].name, g_headerLunch[SIP_CONTACT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (hdr->svr)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
			if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			if (ROUTE_MAPPED != hdr->routetype)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'F':
		{
			if (ROUTE_MAPPED != hdr->routetype)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleFromLine(hdr, fromTag, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'o':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || strncmp(pread, g_bodyLunch[SIP_OWNER].name, g_bodyLunch[SIP_OWNER].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Ower, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateOwnerLine(&pread, &readLen, &pwrite, &newLen, lipStr, serverIp))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'c':
		{
			if ((ROUTE_MAPPED != hdr->routetype) || strncmp(pread, g_bodyLunch[SIP_CONNECTION].name, g_bodyLunch[SIP_CONNECTION].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("Connection, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateConnectionLine(&pread, &readLen, &pwrite, &newLen, lipStr, serverIp))
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'm':
		{
			if ((strncmp(pread, g_bodyLunch[SIP_MEDIA_AUDIO].name, g_bodyLunch[SIP_MEDIA_AUDIO].len))
				&& (strncmp(pread, g_bodyLunch[SIP_MEDIA_VIDEO].name, g_bodyLunch[SIP_MEDIA_VIDEO].len)))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("m=audio or m=video, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if ('a' == *(pread + 2))
			{
				if (PARSER_OK != sip_updateMediaLine(hdr, SIP_MEDIA_AUDIO, &pread, &readLen,
					&pwrite, &newLen, lipStr, serverIp, fromTag))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				if (PARSER_OK != sip_updateMediaLine(hdr, SIP_MEDIA_VIDEO, &pread, &readLen,
					&pwrite, &newLen, lipStr, serverIp, fromTag))
				{
					return PARSER_ERROR;
				}
			}
			break;
		}

		case 'a':
		{
			if (strncmp(pread, g_bodyLunch[SIP_MEDIA_ALT].name, g_bodyLunch[SIP_MEDIA_ALT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			SCLogInfo("a=alt, ip(%s)[%s:%d]", lipStr, __func__, __LINE__);
			if (PARSER_OK != sip_updateMediaLine(hdr, SIP_MEDIA_ALT, &pread, &readLen,
				&pwrite, &newLen, lipStr, serverIp, fromTag))
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateAckIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateAckIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr)
{
	int ret;
	int newLen;
	int readLen;
	char *pread = NULL;
	char *pwrite = NULL;

	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	while (0 < readLen)
	{
		/* c<->s */
		switch (*pread)
		{
		case 'A':
		{
			if (strncmp(pread, g_methodLunch[SIP_ACK].name, g_methodLunch[SIP_ACK].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (NULL == hdr->svr)
			{
				if (strnstr(data, g_headerLunch[SIP_CONTACT].name, len))
				{
					sip_writeLine(&pwrite, &pread, &readLen, &newLen);
					break;
				}
			}

			if (hdr->svr)
			{
				SCLogInfo("Ack, ip(%s), port(%u)[%s:%d]", sipStr, hdr->udp->source, __func__, __LINE__);
				if (PARSER_OK != sip_updateRequestLine(hdr, SIP_ACK, &pread, &readLen,
					&pwrite, &newLen, sipStr, hdr->udp->source))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				SCLogInfo("Ack, ip(%s)[%s:%d]", dipStr, __func__, __LINE__);
				if (PARSER_OK != sip_updateRequestLine(hdr, SIP_ACK, &pread, &readLen, &pwrite, &newLen, dipStr, 0))
				{
					return PARSER_ERROR;
				}
			}
			break;
		}

		case 'V':
		{
			ret = sip_handleMethodViaLine(hdr, lipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'R':
		{
			ret = sip_handleRouteLine(hdr, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'C':
		{
			if (strncmp(pread, g_headerLunch[SIP_CONTACT].name, g_headerLunch[SIP_CONTACT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (NULL == hdr->svr)
			{
				SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
				if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}

	*contentLen = newLen;
	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateCancelIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateCancelIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr)
{
	int ret;
	int newLen;
	int readLen;
	char *pread = NULL;
	char *pwrite = NULL;
	char fromTag[SIP_TAG_BUFF_LEN];
	char serverIp[SIP_IP_BUFF_SIZE];

	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	memset(fromTag, 0, SIP_TAG_BUFF_LEN);
	memset(serverIp, 0, SIP_IP_BUFF_SIZE);
	while (0 < readLen)
	{
		switch (*pread)
		{
		case 'C':
		{
			if ((strncmp(pread, g_methodLunch[SIP_CANCEL].name, g_methodLunch[SIP_CANCEL].len))
				&& (strncmp(pread, g_methodLunch[SIP_CONTACT].name, g_methodLunch[SIP_CONTACT].len)))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if ('A' == *(pread + 1))
			{
				/* cancel */
				if (hdr->svr)
				{
					SCLogInfo("Cancel, ip(%s), port(%u)[%s:%d]", sipStr, hdr->udp->source, __func__, __LINE__);
					if (PARSER_OK != sip_updateRequestLine(hdr, SIP_CANCEL, &pread, &readLen,
						&pwrite, &newLen, sipStr, hdr->udp->source))
					{
						return PARSER_ERROR;
					}
				}
				else
				{
					SCLogInfo("Cancel, ip(%s)[%s:%d]", dipStr, __func__, __LINE__);
					if (PARSER_OK != sip_updateRequestLine(hdr, SIP_CANCEL, &pread, &readLen, &pwrite, &newLen, dipStr, 0))
					{
						return PARSER_ERROR;
					}
				}
			}
			else
			{
				/* contact */
				if (hdr->svr)
				{
					sip_writeLine(&pwrite, &pread, &readLen, &newLen);
					break;
				}

				SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
				if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
				{
					return PARSER_ERROR;
				}
			}

			break;
		}

		case 'V':
		{
			ret = sip_handleMethodViaLine(hdr, lipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'R':
		{
			ret = sip_handleRouteLine(hdr, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, NULL, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, fromTag, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}
	*contentLen = newLen;
	sip_delTagRoutes(hdr, fromTag, NULL);
	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateByeIpPort
*Action      : update ip and port
*Input       : data         input data
			   len          input data length
			   dipStr       dest ip string
			   lipStr       local ip string
*Output      : content      output data
			   contentLen   output data length
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.1.6
*Instruction : null
************************************************************/
static int sip_updateByeIpPort(struct filter_header *hdr, char *data, int len, char *content,
	int *contentLen, char *sipStr, char *dipStr, char *lipStr)
{
	int ret;
	int newLen;
	int viaCnt;
	int readLen;
	char *pread = NULL;
	char *pwrite = NULL;
	char fromTag[SIP_TAG_BUFF_LEN];
	char toTag[SIP_TAG_BUFF_LEN];

	viaCnt = 0;
	newLen = 0;
	readLen = len;
	pread = data;
	pwrite = content;
	memset(fromTag, 0, SIP_TAG_BUFF_LEN);
	memset(toTag, 0, SIP_TAG_BUFF_LEN);
	while (0 < readLen)
	{
		/* c<->s */
		switch (*pread)
		{
		case 'B':
		{
			if (strncmp(pread, g_methodLunch[SIP_BYE].name, g_methodLunch[SIP_BYE].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (hdr->svr)
			{
				SCLogInfo("Bye, ip(%s), port(%u)[%s:%d]", sipStr, hdr->udp->source, __func__, __LINE__);
				if (PARSER_OK != sip_updateRequestLine(hdr, SIP_BYE, &pread, &readLen,
					&pwrite, &newLen, sipStr, hdr->udp->source))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			}
			break;
		}

		case 'V':
		{
			if (viaCnt)
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			ret = sip_handleMethodViaLine(hdr, lipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}

			viaCnt = 1;
			break;
		}

		case 'C':
		{
			if (strncmp(pread, g_headerLunch[SIP_CONTACT].name, g_headerLunch[SIP_CONTACT].len))
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
				break;
			}

			if (NULL == hdr->svr)
			{
				SCLogInfo("Contact, ip(%s), port(%u)[%s:%d]", lipStr, hdr->localport, __func__, __LINE__);
				if (PARSER_OK != sip_updateContactLine(&pread, &readLen, &pwrite, &newLen, lipStr, hdr->localport))
				{
					return PARSER_ERROR;
				}
			}
			else
			{
				sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			}
			break;
		}

		case 'F':
		{
			ret = sip_handleFromLine(hdr, fromTag, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'T':
		{
			ret = sip_handleToLine(hdr, toTag, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		case 'R':
		{
			ret = sip_handleRouteLine(hdr, lipStr, dipStr, &pread, &readLen, &pwrite, &newLen);
			if (PARSER_CONTINUE == ret)
			{
				break;
			}

			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
			break;
		}

		default:
		{
			sip_writeLine(&pwrite, &pread, &readLen, &newLen);
			break;
		}
		}
	}
	*contentLen = newLen;
	sip_delTagRoutes(hdr, fromTag, toTag);
	return PARSER_OK;
}

static int sip_handleMethod(struct filter_header *hdr, char *data, int len, char *sipStr, char *dipStr, char *lipStr)
{
	int ret;
	int contentLen;
	char content[SIP_BUFF_DATA_LEN];

	if (!strncmp(data, g_methodLunch[SIP_REGISTER].name, g_methodLunch[SIP_REGISTER].len))
	{
		SCLogInfo("method(%s)[%s:%d]", g_methodLunch[SIP_REGISTER].name, __func__, __LINE__);
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_updateRegisterIpPort(hdr, data, len, content, &contentLen, dipStr, lipStr);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
		}
		else
		{
			sip_getSessionData(data, len, content, &contentLen);
		}
	}
	else if (!strncmp(data, g_methodLunch[SIP_SUBSCRIBE].name, g_methodLunch[SIP_SUBSCRIBE].len))
	{
		SCLogInfo("method(%s)[%s:%d]", g_methodLunch[SIP_SUBSCRIBE].name, __func__, __LINE__);
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_updateSubscribeIpPort(hdr, data, len, content, &contentLen, dipStr, lipStr);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
		}
		else
		{
			sip_getSessionData(data, len, content, &contentLen);
		}
	}
	else if (!strncmp(data, g_methodLunch[SIP_INVITE].name, g_methodLunch[SIP_INVITE].len))
	{
		SCLogInfo("method(%s)[%s:%d]", g_methodLunch[SIP_INVITE].name, __func__, __LINE__);
		ret = sip_updateInviteIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr);
		if (PARSER_OK != ret)
		{
			return PARSER_ERROR;
		}
	}
	else if (!strncmp(data, g_methodLunch[SIP_ACK].name, g_methodLunch[SIP_ACK].len))
	{
		SCLogInfo("method(%s)[%s:%d]", g_methodLunch[SIP_ACK].name, __func__, __LINE__);
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_updateAckIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
		}
		else
		{
			sip_getSessionData(data, len, content, &contentLen);
		}
	}
	else if (!strncmp(data, g_methodLunch[SIP_CANCEL].name, g_methodLunch[SIP_CANCEL].len))
	{
		SCLogInfo("method(%s)[%s:%d]", g_methodLunch[SIP_CANCEL].name, __func__, __LINE__);
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_updateCancelIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
		}
		else
		{
			sip_getSessionData(data, len, content, &contentLen);
		}
	}
	else if (!strncmp(data, g_methodLunch[SIP_BYE].name, g_methodLunch[SIP_BYE].len))
	{
		SCLogInfo("method(%s)[%s:%d]", g_methodLunch[SIP_BYE].name, __func__, __LINE__);
		if (ROUTE_MAPPED == hdr->routetype)
		{
			ret = sip_updateByeIpPort(hdr, data, len, content, &contentLen, sipStr, dipStr, lipStr);
			if (PARSER_OK != ret)
			{
				return PARSER_ERROR;
			}
		}
		else
		{
			sip_getSessionData(data, len, content, &contentLen);
		}
	}
	else
	{
		contentLen = len;
		strncpy(content, data, len);
	}

	if (ROUTE_MAPPED == hdr->routetype)
	{
		sip_updateContentLength(content, &contentLen);
	}

	SCLogInfo("send to req, len(%d), ssid(%u)[%s:%d]\n", contentLen, hdr->sessionid, __func__, __LINE__);
	if (0 != buffer_sendtoreq(hdr, content, contentLen))
	{
		SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateAndSendData
*Action      : update and send data
*Input       : hdr      packet processing header information
			   data     data
			   len      data length
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.5
*Instruction : null
************************************************************/
static int sip_updateAndSendData(struct filter_header *hdr, char *data, int len)
{
	int ret;
	char cseqType[SIP_CSEQ_BUFF_LEN];
	char sipStr[SIP_IP_BUFF_SIZE];
	char dipStr[SIP_IP_BUFF_SIZE];
	char lipStr[SIP_IP_BUFF_SIZE];

	/* Get cseqType type */
	ret = sip_getCseqType(data, len, cseqType);
	if (PARSER_OK != ret)
	{
		/* not find */
		if (0 != buffer_sendtoreq(hdr, data, len))
		{
			SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}
		return PARSER_OK;
	}

	IP_NUM_TO_STR(hdr->ip->saddr, sipStr, SIP_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->ip->daddr, dipStr, SIP_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->localip, lipStr, SIP_IP_BUFF_SIZE);

	SCLogInfo("from forward, data(%p), len(%d), sip(%s), sport(%u), dip(%s), dport(%u), lip(%s), lport(%u), ssid(%u)[%s:%d]",
		data, len, sipStr, hdr->udp->source, dipStr, hdr->udp->dest,
		lipStr, hdr->localport, hdr->sessionid, __func__, __LINE__);

	if (!strncmp(data, g_methodLunch[SIP_SIP].name, g_methodLunch[SIP_SIP].len))
	{
		ret = sip_handleStatus(hdr, data, len, sipStr, dipStr, lipStr, cseqType);
	}
	else
	{
		ret = sip_handleMethod(hdr, data, len, sipStr, dipStr, lipStr);
	}

	return ret;
}
#endif

#if GAP_DESC("client response message")
/************************************************************
*Function    : sip_updateCltEventRspbufData
*Action      : check the full session in rspbuf
*Input       : hdr          packet processing header information
			   evnetBuf     event buffer
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int sip_updateCltEventRspbufData(struct filter_header *hdr, struct evbuffer *evnetBuf)
{
	int result;
	int bodyLen;
	ev_ssize_t ret;
	size_t eventBufLen;
	struct evbuffer_ptr pos;
	char data[SIP_BUFF_DATA_LEN];

	while (1)
	{
		/* Get data length of response eventbuffer */
		eventBufLen = evbuffer_get_length(evnetBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check head data all receive */
		pos = evbuffer_search(evnetBuf, "\r\n\r\n", 4, NULL);
		if (-1 == pos.pos)
		{
			break;
		}

		/* Get header */
		ret = evbuffer_copyout(evnetBuf, data, pos.pos + 4);
		if (-1 == ret)
		{
			SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body length */
		result = sip_getBodyLen(data, (int)(pos.pos) + 4, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			if (0 != evbuffer_sendtoreq(hdr, evnetBuf, pos.pos + 4))
			{
				SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			continue;
		}

		/* Check body data all receive */
		if (eventBufLen < (pos.pos + 4 + (size_t)bodyLen))
		{
			break;
		}

		/* Delete header */
		if (0 != evbuffer_drain(evnetBuf, pos.pos + 4))
		{
			SCLogError("drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body to cache */
		if (0 < bodyLen)
		{
			ret = evbuffer_remove(evnetBuf, data + (int)(pos.pos) + 4, bodyLen);
			if (-1 == ret)
			{
				SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		/* Update and send */
		result = sip_updateAndSendData(hdr, data, (pos.pos + 4 + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateCltRspbufData
*Action      : update the full session in buff
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
static int sip_updateCltRspbufData(struct filter_header *hdr, struct evbuffer *evnetBuf, char *buff, int len)
{
	int result;
	int offset;
	int bodyLen;
	char *pos = NULL;

	while (1)
	{
		/* Get data length of response buff */
		if (0 >= len)
		{
			break;
		}

		/* Check head data all receive */
		pos = strnstr(buff, "\r\n\r\n", len);
		if (NULL == pos)
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Get body data length */
		offset = (int)(pos - buff) + 4;
		result = sip_getBodyLen(buff, offset, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			if (0 != buffer_sendtoreq(hdr, buff, offset))
			{
				SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			buff = pos + 4;
			len -= offset;
			continue;
		}

		/* Check body data all receive */
		if (len < (offset + bodyLen))
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Update and send */
		result = sip_updateAndSendData(hdr, buff, (offset + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}

		buff = pos + 4 + bodyLen;
		len -= (offset + bodyLen);
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_handleClientRsp
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
static int sip_handleClientRsp(struct filter_header *hdr, SIP_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		/* Client handle: rsp buffer and this data */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("add data to session rsp buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			if (PARSER_OK != sip_updateCltEventRspbufData(hdr, session->rspBuf))
			{
				return PARSER_ERROR;
			}
		}
	}
	else
	{
		/* Client handle: this data */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			if (PARSER_OK != sip_updateCltRspbufData(hdr, session->rspBuf,
				(char *)(obj->buffdata.data), (int)(obj->buffdata.len)))
			{
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server response message")
/************************************************************
*Function    : sip_updateSvrEventRspbufData
*Action      : check the full session in rspbuf
*Input       : hdr          packet processing header information
			   evnetBuf     event buffer
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int sip_updateSvrEventRspbufData(struct filter_header *hdr, struct evbuffer *evnetBuf)
{
	int result;
	int bodyLen;
	ev_ssize_t ret;
	size_t eventBufLen;
	struct evbuffer_ptr pos;
	char data[SIP_BUFF_DATA_LEN];

	while (1)
	{
		/* Get data length of response eventbuffer */
		eventBufLen = evbuffer_get_length(evnetBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check head data all receive */
		pos = evbuffer_search(evnetBuf, "\r\n\r\n", 4, NULL);
		if (-1 == pos.pos)
		{
			break;
		}

		/* Get header */
		ret = evbuffer_copyout(evnetBuf, data, pos.pos + 4);
		if (-1 == ret)
		{
			SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body length */
		result = sip_getBodyLen(data, (int)(pos.pos) + 4, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			if (0 != evbuffer_sendtoreq(hdr, evnetBuf, pos.pos + 4))
			{
				SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			continue;
		}

		/* Check body data all receive */
		if (eventBufLen < (pos.pos + 4 + (size_t)bodyLen))
		{
			break;
		}

		/* Delete header */
		if (0 != evbuffer_drain(evnetBuf, pos.pos + 4))
		{
			SCLogError("drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body to cache */
		if (0 < bodyLen)
		{
			ret = evbuffer_remove(evnetBuf, data + (int)(pos.pos) + 4, bodyLen);
			if (-1 == ret)
			{
				SCLogError("copy data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		/* Update and send */
		result = sip_updateAndSendData(hdr, data, (pos.pos + 4 + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_updateSvrRspbufData
*Action      : update the full session in buff
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
static int sip_updateSvrRspbufData(struct filter_header *hdr, struct evbuffer *evnetBuf, char *buff, int len)
{
	int result;
	int offset;
	int bodyLen;
	char *pos = NULL;

	while (1)
	{
		/* Get data length of response buff */
		if (0 >= len)
		{
			break;
		}

		/* Check head data all receive */
		pos = strnstr(buff, "\r\n\r\n", len);
		if (NULL == pos)
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Get body data length */
		offset = (int)(pos - buff) + 4;
		result = sip_getBodyLen(buff, offset, &bodyLen);
		if (PARSER_ERROR == result)
		{
			return PARSER_ERROR;
		}

		if (PARSER_CONTINUE == result)
		{
			if (0 != buffer_sendtoreq(hdr, buff, offset))
			{
				SCLogError("send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			buff = pos + 4;
			len -= offset;
			continue;
		}

		/* Check body data all receive */
		if (len < (offset + bodyLen))
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(evnetBuf, buff, len))
			{
				SCLogError("add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Update and send */
		result = sip_updateAndSendData(hdr, buff, (offset + bodyLen));
		if (PARSER_OK != result)
		{
			return PARSER_ERROR;
		}

		buff = pos + 4 + bodyLen;
		len -= (offset + bodyLen);
	}

	return PARSER_OK;
}

/************************************************************
*Function    : sip_handleClientRsp
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
static int sip_handleServerRsp(struct filter_header *hdr, SIP_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		/* Server handle: rsp buffer and this data */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("add data to session rsp buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			if (PARSER_OK != sip_updateSvrEventRspbufData(hdr, session->rspBuf))
			{
				return PARSER_ERROR;
			}
		}
	}
	else
	{
		/* Server handle: this data */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			if (PARSER_OK != sip_updateSvrRspbufData(hdr, session->rspBuf,
				(char *)(obj->buffdata.data), (int)(obj->buffdata.len)))
			{
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

/************************************************************
*Function    : sip_checkFwdObjData
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
static int sip_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
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
*Function    : sip_data
*Action      : SIP protocol data processing
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
static enum FLT_RET sip_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SIP_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("invalid para, hdr(%p)[%s:%d]", hdr, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = sip_allocSession();
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
			return sip_closeSession(hdr, (int)len, "User data is NULL");
		}

		session = hdr->user;

		SCLogInfo("on socket data, len(%u), sessionid(%u)[%s:%d]", (unsigned int)len, hdr->sessionid, __func__, __LINE__);

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != sip_handleClientReq(hdr, session, buff, len))
			{
				return sip_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (PARSER_OK != sip_handleServerReq(hdr, session, buff, len))
			{
				return sip_closeSession(hdr, (int)len, "Handle server request data");
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
			return sip_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("invalid para, buff(%p), len(%u)[%s:%d]", buff, (unsigned int)len, __func__, __LINE__);
			return sip_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		SCLogInfo("receive data from fwd, len(%u), sessionid(%u)[%s:%d]",
			(unsigned int)obj->buffdata.len, hdr->sessionid, __func__, __LINE__);

		if (PARSER_OK != sip_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != sip_handleClientRsp(hdr, session, obj))
			{
				return sip_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != sip_handleServerRsp(hdr, session, obj))
			{
				return sip_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return sip_closeSession(hdr, 0, NULL);
	}

	case FLTEV_ONSVROK:         /* Not handle, return ok */
	default:
		break;

	}

	return FLTRET_OK;
}

/************************************************************
*Function    : sip_free
*Action      : sip free
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int sip_free(void)
{
	return PARSER_OK;
}

/************************************************************
*Function    : sip_init
*Action      : sip init
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int sip_init(void)
{
	unsigned int size;

	if ((1024 > g_gapcfg->port_sip_begin) || (g_gapcfg->port_sip_begin > g_gapcfg->port_sip_end))
	{
		SCLogError("invalid begin port(%u) and end port(%u), please check[%s:%d]",
			g_gapcfg->port_sip_begin, g_gapcfg->port_sip_end, __func__, __LINE__);
		return PARSER_ERROR;
	}

	g_sipDynamicPortNum = (unsigned short)(g_gapcfg->port_sip_end - g_gapcfg->port_sip_begin + 1);
	size = ((unsigned int)g_sipDynamicPortNum) * ((unsigned int)sizeof(SIP_DYNAMIC_PORT));
	g_sipDynamicPort = (SIP_DYNAMIC_PORT *)SCMalloc(size);
	if (NULL == g_sipDynamicPort)
	{
		g_sipDynamicPortNum = 0;
		SCLogError("SCMalloc memory failed, size(%u)[%s:%d]", size, __func__, __LINE__);
		return PARSER_ERROR;
	}
	memset(g_sipDynamicPort, 0, size);

	return PARSER_OK;
}

/************************************************************
*Function    : sip_checkData
*Action      : sip check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID sip_checkData(const void *buff, size_t len)
{
	if ((9 < len) && (!memcmp(buff, "REGISTER ", 9) || !memcmp(buff, "INVITE ", 7)))
	{
		return SVR_ID_SIP;
	}
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_sip
*Action      : sip protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static struct packet_filter g_filter_sip =
{
	SVR_ID_SIP,
	"sip parser",
	sip_init,
	sip_data,
	sip_free,
	sip_checkData
};

PROTOCOL_FILTER_OP(sip)

