/********************************************************************************

		   Copyright (C), 2016, 2016, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_rtsp.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2016.12.23
Description    : RTSP protocol process
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
#include "parser_rtsp.h"

/* System port number */
static unsigned short g_rtspDynamicPortNum = 0;

/* Dynamic port service information */
static RTSP_DYNAMIC_PORT *g_rtspDynamicPort = NULL;

/************************************************************
*Function    : rtsp_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static RTSP_SESSION *rtsp_allocSession(void)
{
	RTSP_SESSION *session = NULL;

	session = SCMalloc(sizeof(RTSP_SESSION));
	if (NULL == session)
	{
		SCLogError("[RTSP]SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)sizeof(RTSP_SESSION), __func__, __LINE__);
		return NULL;
	}

	memset(session, 0, sizeof(*session));

	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("[RTSP]evbuffer_new failed[%s:%d]", __func__, __LINE__);
		SCFree(session);
		session = NULL;
		return NULL;
	}

	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("[RTSP]evbuffer_new failed[%s:%d]", __func__, __LINE__);
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}

	session->connecting = RTSP_DISCONNECT;
	return session;
}

/************************************************************
*Function    : rtsp_freeSession
*Action      : free session
*Input       : session  session obj
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static void rtsp_freeSession(RTSP_SESSION *session)
{
	RTSP_NEW_ROUTE *rtspRoute = NULL;

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

	while (session->routes)
	{
		rtspRoute = session->routes;
		session->routes = rtspRoute->next;
		if (rtspRoute->data_svr)
		{
			server_free(rtspRoute->data_svr);
			rtspRoute->data_svr = NULL;
		}
		SCFree(rtspRoute);
		rtspRoute = NULL;
	}

	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : rtsp_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
void rtsp_writeSeceventLog(struct filter_header *hdr, int packLen, char *content, enum SVR_ID svrId)
{
	char sip[PARSER_IP_BUFF_SIZE];
	char dip[PARSER_IP_BUFF_SIZE];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;
	char *groupName = NULL;

	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	proto = (char*)server_strfromid(svrId);
	aclData = (struct acl_data *)(hdr->private);
	if (SVR_ID_RTSP == svrId)
	{
		groupName = aclData->groupname;
		INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
			aclData->user, "none", l_critical, groupName, "false", packLen, content);
	}
	else
	{
		groupName = (hdr->svr) ? (hdr->svr->parent_acldata->groupname) : "";
		INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 17, (int)(hdr->udp->source), (int)(hdr->udp->dest), proto,
			aclData->user, "none", l_critical, groupName, "false", packLen, content);
	}
}

static void rtsp_delLocalPort(struct server *svr)
{
	unsigned short index;

	for (index = 0; index < g_rtspDynamicPortNum; index++)
	{
		if (g_rtspDynamicPort[index].isUsed)
		{
			if (g_rtspDynamicPort[index].svr == svr)
			{
				g_rtspDynamicPort[index].svr = NULL;
				g_rtspDynamicPort[index].isUsed = PARSER_BFALSE;
			}
		}
	}
	return;
}

static int rtsp_getLocalPort(unsigned short *localPort1, unsigned short *localPort2)
{
	unsigned short index;

	for (index = 0; index < g_rtspDynamicPortNum - 1; index++)
	{
		if ((!g_rtspDynamicPort[index].isUsed) && (!g_rtspDynamicPort[index + 1].isUsed))
		{
			g_rtspDynamicPort[index].isUsed = PARSER_BTRUE;
			g_rtspDynamicPort[index + 1].isUsed = PARSER_BTRUE;
			*localPort1 = index + g_gapcfg->port_rtsp_begin;
			*localPort2 = index + 1 + g_gapcfg->port_rtsp_begin;
			return PARSER_OK;
		}
	}

	return PARSER_ERROR;
}

static int rtsp_setLocalPort(unsigned short localPort, struct server *svr)
{
	unsigned short index;

	if ((g_gapcfg->port_rtsp_begin > localPort) || (g_gapcfg->port_rtsp_end < localPort))
	{
		SCLogError("[RTSP]invalid port(%u), range[%u, %u][%s:%d]",
			localPort, g_gapcfg->port_rtsp_begin, g_gapcfg->port_rtsp_end, __func__, __LINE__);
		return PARSER_ERROR;
	}

	index = localPort - g_gapcfg->port_rtsp_begin;
	if (!g_rtspDynamicPort[index].isUsed)
	{
		SCLogError("[RTSP]localPort(%u) not used[%s:%d]", localPort, __func__, __LINE__);
		return PARSER_ERROR;
	}

	g_rtspDynamicPort[index].svr = svr;
	return PARSER_OK;
}

static void rtsp_unsetAllSessionSvr(struct filter_header *hdr, RTSP_NEW_ROUTE *routes)
{
	RTSP_NEW_ROUTE *rtspRoute = NULL;

	while (routes)
	{
		rtspRoute = routes;
		routes = routes->next;
		hdr->svr_remove_cb(hdr, rtspRoute->data_svr);
		rtsp_delLocalPort(rtspRoute->data_svr);
	}
	return;
}

/************************************************************
*Function    : rtsp_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET rtsp_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	RTSP_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogWarning("[RTSP]invalid para, hdr(%p), user(%p), maybe session is closed[%s:%d]", hdr, hdr->user, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		rtsp_writeSeceventLog(hdr, packLen, content, SVR_ID_RTSP);
	}

	session = hdr->user;

	if (NULL != session->routes)
	{
		rtsp_unsetAllSessionSvr(hdr, session->routes);
	}

	rtsp_freeSession(session);
	hdr->user = NULL;

	SCLogInfo("[RTSP]on socket close, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);

	return FLTRET_CLOSE;
}

#if GAP_DESC("client request message")
/************************************************************
*Function    : rtsp_handleClientReq
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
static int rtsp_handleClientReq(struct filter_header *hdr, RTSP_SESSION *session, const void *buff, size_t len)
{
	/* Send request eventbuffer */
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[RTSP]add data to session req buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[RTSP]send session buffer data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
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
				SCLogError("[RTSP]send data to forward failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server request message")
/************************************************************
*Function    : rtsp_handleServerReq
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
static int rtsp_handleServerReq(struct filter_header *hdr, RTSP_SESSION *session, const void *buff, size_t len)
{
	return rtsp_handleClientReq(hdr, session, buff, len);
}
#endif

/************************************************************
*Function    : rtsp_checkFwdObjData
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
static int rtsp_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
{
	if (obj->cmd != FWDCMD_FORWARDDATA)
	{
		SCLogError("[RTSP]not fwd event type, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (0 == obj->has_buffdata)
	{
		SCLogError("[RTSP]obj data is null, sessionid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

#if GAP_DESC("client response message")
static RTSP_NEW_ROUTE *rtsp_setSvrToSession(struct filter_header *hdr, struct server *svr)
{
	RTSP_SESSION *session = NULL;
	RTSP_NEW_ROUTE *rtspRoute = NULL;

	session = hdr->user;
	rtspRoute = (RTSP_NEW_ROUTE *)SCMalloc(sizeof(RTSP_NEW_ROUTE));
	if (NULL == rtspRoute)
	{
		SCLogError("[RTSP]SCMalloc memory failed, size(%u)[%s:%d]", (unsigned int)sizeof(RTSP_NEW_ROUTE), __func__, __LINE__);
		return NULL;
	}

	rtspRoute->data_svr = svr;
	rtspRoute->next = session->routes;
	session->routes = rtspRoute;

	return rtspRoute;
}

static int rtsp_createDataSvr(struct filter_header *hdr, char *localIp, char *serverIp,
	unsigned short localPort1, unsigned short serverPort1,
	unsigned short localPort2, unsigned short serverPort2)
{
	struct server *mgrSvr = NULL;
	struct server *dataSvr = NULL;
	RTSP_NEW_ROUTE *rtspRoute = NULL;

	if (ROUTE_MAPPED == hdr->routetype)
	{
		mgrSvr = server_new(SVR_ID_RTSPDATA, "rtspdata server", localIp, localPort1, serverIp, serverPort1);
	}
	else
	{
		mgrSvr = server_new(SVR_ID_RTSPDATA, "rtspdata server", localIp, 0, serverIp, serverPort1);
	}
	if (mgrSvr == NULL)
	{
		SCLogError("[RTSP]server_new memory failed, size(%u), sessionid(%u)[%s:%d]",
			(unsigned int)sizeof(struct server), hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (PARSER_OK != rtsp_setLocalPort(localPort1, mgrSvr))
	{
		rtsp_delLocalPort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;
		return PARSER_ERROR;
	}

	hdr->svr_add_cb(hdr, mgrSvr);
	rtspRoute = rtsp_setSvrToSession(hdr, mgrSvr);
	if (NULL == rtspRoute)
	{
		hdr->svr_remove_cb(hdr, mgrSvr);
		rtsp_delLocalPort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;
	}
	SCLogInfo("[RTSP]add rtspdata route(%s:%u --> %s:%u), svr(%p), sessionid(%u)[%s:%d]",
		localIp, (ROUTE_MAPPED == hdr->routetype) ? localPort1 : 0, serverIp,
		serverPort1, mgrSvr, hdr->sessionid, __func__, __LINE__);

	if (ROUTE_MAPPED == hdr->routetype)
	{
		dataSvr = server_new(SVR_ID_RTSPDATA, "rtspdata server", localIp, localPort2, serverIp, serverPort2);
	}
	else
	{
		dataSvr = server_new(SVR_ID_RTSPDATA, "rtspdata server", localIp, 0, serverIp, serverPort2);
	}
	if (dataSvr == NULL)
	{
		SCLogError("[RTSP]server_new memory failed, size(%u), sessionid(%u)[%s:%d]",
			(unsigned int)sizeof(struct server), hdr->sessionid, __func__, __LINE__);
		hdr->svr_remove_cb(hdr, mgrSvr);
		rtsp_delLocalPort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;
		return PARSER_ERROR;
	}

	if (PARSER_OK != rtsp_setLocalPort(localPort2, dataSvr))
	{
		hdr->svr_remove_cb(hdr, mgrSvr);
		rtsp_delLocalPort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;

		rtsp_delLocalPort(dataSvr);
		server_free(dataSvr);
		dataSvr = NULL;
		return PARSER_ERROR;
	}

	hdr->svr_add_cb(hdr, dataSvr);
	if (NULL == rtsp_setSvrToSession(hdr, dataSvr))
	{
		hdr->svr_remove_cb(hdr, mgrSvr);
		rtsp_delLocalPort(mgrSvr);
		server_free(mgrSvr);
		mgrSvr = NULL;

		hdr->svr_remove_cb(hdr, dataSvr);
		rtsp_delLocalPort(dataSvr);
		server_free(dataSvr);
		dataSvr = NULL;
	}
	SCLogInfo("[RTSP]add rtspdata route(%s:%u --> %s:%u), svr(%p), sessionid(%u)[%s:%d]",
		localIp, (ROUTE_MAPPED == hdr->routetype) ? localPort2 : 0, serverIp,
		serverPort2, dataSvr, hdr->sessionid, __func__, __LINE__);

	return PARSER_OK;
}

static void rtsp_replaceData(char **pRead, char **pWrite, int *newLen,
	char endChar, char *replaceData, int *leftLen,
	char *key, int keyLen)
{
	int offset;
	char *pend = NULL;

	if (!strncmp(*pRead, key, keyLen))
	{
		pend = strchr((*pRead) + keyLen, endChar);
		if (pend)
		{
			memcpy(*pWrite, key, keyLen);
			(*pWrite) += keyLen;
			(*newLen) += keyLen;
			offset = strlen(replaceData);
			memcpy(*pWrite, replaceData, offset);
			(*pWrite) += offset;
			(*newLen) += offset;
			offset = (int)(pend - (*pRead));
			(*leftLen) -= offset;
			(*pRead) = pend;
			return;
		}
	}

	(**pWrite) = (**pRead);
	(*pRead)++;
	(*leftLen)--;
	(*pWrite)++;
	(*newLen)++;
	return;
}

static void rtsp_updataContentLen(char *data, int len, int *sendLen)
{
	int oldLen;
	int newLen;
	int offset;
	char newLenStr[PARSER_COMMON_LEN];
	char *pContent = NULL;
	char *pContentLengthStart = NULL;
	char *pContentLengthEnd = NULL;

	pContentLengthStart = strnstr(data, "Content-Length: ", len);
	if (pContentLengthStart)
	{
		pContentLengthStart += 16;
		pContentLengthEnd = strchr(pContentLengthStart, '\r');
		if (NULL == pContentLengthEnd)
		{
			pContentLengthEnd = strchr(pContentLengthStart, '\n');
		}

		if (pContentLengthEnd)
		{
			offset = len - (int)(pContentLengthStart - data);
			pContent = strnstr(pContentLengthStart, "\r\n\r\n", offset);
			if (pContent)
			{
				pContent += RTSP_END_TAG_LEN;
				oldLen = (int)(pContentLengthEnd - pContentLengthStart);
				offset = len - (int)(pContent - data);
				snprintf(newLenStr, PARSER_COMMON_LEN, "%d", offset);
				newLen = strlen(newLenStr);
				//SCLogInfo("[RTSP]oldLen:%d, newLen:%d[%s:%d]", oldLen, newLen, __func__, __LINE__);
				if (oldLen == newLen)
				{
					memcpy(pContentLengthStart, newLenStr, newLen);
				}
				else if (oldLen > newLen)
				{
					memcpy(pContentLengthStart, newLenStr, newLen);
					offset = len - (int)(pContentLengthEnd - data);
					memcpy(pContentLengthStart + newLen, pContentLengthEnd, offset);
					offset = oldLen - newLen;
					*sendLen -= offset;
				}
				else
				{
					offset = len - (int)(pContentLengthEnd - data);
					memmove(pContentLengthStart + newLen, pContentLengthEnd, offset);
					memcpy(pContentLengthStart, newLenStr, newLen);
					offset = newLen - oldLen;
					*sendLen += offset;
				}
			}
		}
	}

	return;
}

static int rtsp_replaceIpPort(struct filter_header *hdr, char *data, int *len, char *replaceIp, char *replacePort)
{
	int newLen;
	int leftLen;
	char *pWrite = NULL;
	char *pRead = NULL;
	char newData[RTSP_SESSION_BUFF_LEN];

	memset(newData, 0, RTSP_SESSION_BUFF_LEN);
	newLen = 0;
	leftLen = *len;
	pWrite = newData;
	pRead = data;
	while (0 < leftLen)
	{
		switch (*pRead)
		{
		case 'r':
		{
			rtsp_replaceData(&pRead, &pWrite, &newLen, ':', replaceIp, &leftLen, RTSP_IP_KEY_STRING, RTSP_IP_KEY_STRING_LEN);
			break;
		}

		case 's':
		{
			rtsp_replaceData(&pRead, &pWrite, &newLen, ';', replacePort, &leftLen, RTSP_SERVER_PORT_KEY, RTSP_PORT_KEY_LEN);
			break;
		}

		case 'c':
		{
			rtsp_replaceData(&pRead, &pWrite, &newLen, '\r', replacePort, &leftLen, RTSP_CLIENT_PORT_KEY, RTSP_PORT_KEY_LEN);
			break;
		}

		default:
		{
			*pWrite = *pRead;
			pRead++;
			leftLen--;
			pWrite++;
			newLen++;
			break;
		}
		}
	}

	if (newLen)
	{
		memcpy(data, newData, newLen);
		*len = newLen;
	}

	/* Updata content length */
	rtsp_updataContentLen(data, newLen, len);

	return PARSER_OK;
}

static int rtsp_updateAndSendCltRspSession(struct filter_header *hdr, char *data, int len, char *replaceIp, char *replacePort)
{
	int dataLen;

	dataLen = len;
	if (ROUTE_MAPPED == hdr->routetype)
	{
		if (PARSER_OK != rtsp_replaceIpPort(hdr, data, &dataLen, replaceIp, replacePort))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		SCLogInfo("[RTSP]route type(%d) is not mapped, not to change response data, sessionid(%u)[%s:%d]",
			hdr->routetype, hdr->sessionid, __func__, __LINE__);
	}

	//SCLogInfo("[RTSP]len:%d data:%s[%s:%d]", dataLen, data, __func__, __LINE__);
	SCLogInfo("[RTSP]send to req, len(%d), ssid(%u)[%s:%d]", dataLen, hdr->sessionid, __func__, __LINE__);
	if (0 != buffer_sendtoreq(hdr, data, dataLen))
	{
		SCLogError("[RTSP]send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

static int rtsp_handleCltRspSession(struct filter_header *hdr, RTSP_SESSION *session, char *data, int len)
{
	unsigned short localPort1;
	unsigned short localPort2;
	int serverPort1;
	int serverPort2;
	char *pServerPort = NULL;
	char sipStr[PARSER_IP_BUFF_SIZE];
	char dipStr[PARSER_IP_BUFF_SIZE];
	char lipStr[PARSER_IP_BUFF_SIZE];
	char localPortStr[PARSER_COMMON_LEN];

	IP_NUM_TO_STR(hdr->ip->saddr, sipStr, PARSER_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->ip->daddr, dipStr, PARSER_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->localip, lipStr, PARSER_IP_BUFF_SIZE);
	SCLogInfo("[RTSP]from forward, data(%p), len(%d), sip(%s), sport(%u), dip(%s), dport(%u), lip(%s), lport(%u), ssid(%u)[%s:%d]",
		data, len, sipStr, hdr->tcp->source, dipStr, hdr->tcp->dest,
		lipStr, hdr->localport, hdr->sessionid, __func__, __LINE__);

	localPort1 = 0;
	localPort2 = 0;
	serverPort1 = 0;
	serverPort2 = 0;
	localPortStr[0] = '\0';
	pServerPort = strnstr(data, RTSP_SERVER_PORT_KEY, len);
	if (pServerPort)
	{
		sscanf(pServerPort, "server_port=%d-%d", &serverPort1, &serverPort2);
		if ((0 != serverPort1) && (0 != serverPort2))
		{
			if (PARSER_OK != rtsp_getLocalPort(&localPort1, &localPort2))
			{
				SCLogError("[RTSP]can't find valid rtsp local port, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			snprintf(localPortStr, PARSER_COMMON_LEN, "%u-%u", localPort1, localPort2);
			if (PARSER_OK != rtsp_createDataSvr(hdr, lipStr, dipStr,
				localPort1, (unsigned short)serverPort1,
				localPort2, (unsigned short)serverPort2))
			{
				return PARSER_ERROR;
			}
		}
		else
		{
			SCLogError("[RTSP]get rtsp server port failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		}
	}

	return rtsp_updateAndSendCltRspSession(hdr, data, len, lipStr, localPortStr);
}

static int rtsp_getBodyLength(struct filter_header *hdr, RTSP_SESSION *session,
	char *data, int len, int *bodyLen)
{
	char *pContentLength = NULL;

	pContentLength = strnstr(data, "Content-Length: ", len);
	if (NULL == pContentLength)
	{
		SCLogError("[RTSP]no find key of Content-Length, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	sscanf(pContentLength, "Content-Length: %d", bodyLen);
	return PARSER_OK;
}

/************************************************************
*Function    : rtsp_updateCltEventRspbufData
*Action      : check the full session in rspbuf
*Input       : hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int rtsp_updateCltEventRspbufData(struct filter_header *hdr, RTSP_SESSION *session)
{
	int headLen;
	int bodyLen;
	int dataLen;
	ev_ssize_t ret;
	size_t eventBufLen;
	struct evbuffer_ptr pos;
	char data[RTSP_SESSION_BUFF_LEN];

	while (1)
	{
		/* Get data length of client response eventbuffer */
		eventBufLen = evbuffer_get_length(session->rspBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check session data all receive */
		pos = evbuffer_search(session->rspBuf, "\r\n\r\n", RTSP_END_TAG_LEN, NULL);
		if (-1 == pos.pos)
		{
			/* Not find, write data to fp */
			break;
		}

		/* Get session head data */
		memset(data, 0, RTSP_SESSION_BUFF_LEN);
		headLen = (int)(pos.pos) + RTSP_END_TAG_LEN;
		ret = evbuffer_copyout(session->rspBuf, data, (size_t)headLen);
		if (-1 == ret)
		{
			SCLogError("[RTSP]remove data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Get body length */
		if (PARSER_OK != rtsp_getBodyLength(hdr, session, data, headLen, &bodyLen))
		{
			//SCLogInfo("[RTSP]len:%d data:%s[%s:%d]", headLen, data, __func__, __LINE__);

			SCLogInfo("[RTSP]send to req, len(%d), ssid(%u)[%s:%d]", headLen, hdr->sessionid, __func__, __LINE__);
			if (0 != buffer_sendtoreq(hdr, data, headLen))
			{
				SCLogError("[RTSP]send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			if (0 != evbuffer_drain(session->rspBuf, (size_t)headLen))
			{
				SCLogError("[RTSP]drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			continue;
		}

		if (0 == bodyLen)
		{
			/* Update and send this session */
			if (PARSER_OK != rtsp_handleCltRspSession(hdr, session, data, headLen))
			{
				return PARSER_ERROR;
			}

			if (0 != evbuffer_drain(session->rspBuf, (size_t)headLen))
			{
				SCLogError("[RTSP]drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			continue;
		}

		if (eventBufLen < (size_t)(headLen + bodyLen))
		{
			break;
		}

		/* Session data all receive */
		dataLen = headLen + bodyLen;
		memset(data, 0, RTSP_SESSION_BUFF_LEN);

		ret = evbuffer_copyout(session->rspBuf, data, (size_t)dataLen);
		if (-1 == ret)
		{
			SCLogError("[RTSP]remove data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		if (!strncmp(data + headLen, "RTSP", 4))
		{
			/* Update and send this session */
			if (PARSER_OK != rtsp_handleCltRspSession(hdr, session, data, headLen))
			{
				return PARSER_ERROR;
			}

			if (0 != evbuffer_drain(session->rspBuf, (size_t)headLen))
			{
				SCLogError("[RTSP]drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
		else
		{
			/* Update and send this session */
			if (PARSER_OK != rtsp_handleCltRspSession(hdr, session, data, dataLen))
			{
				return PARSER_ERROR;
			}

			if (0 != evbuffer_drain(session->rspBuf, (size_t)dataLen))
			{
				SCLogError("[RTSP]drain data from session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtsp_updateCltRspbufData
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
static int rtsp_updateCltRspbufData(struct filter_header *hdr, RTSP_SESSION *session, char *buff, int len)
{
	int headLen;
	int bodyLen;
	int dataLen;
	char *pos = NULL;
	char data[RTSP_SESSION_BUFF_LEN];

	while (1)
	{
		/* Get data length of client response buff */
		if (0 >= len)
		{
			break;
		}

		/* Check session data all receive */
		pos = strnstr(buff, "\r\n\r\n", len);
		if (NULL == pos)
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, buff, len))
			{
				SCLogError("[RTSP]add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Get session head data */
		memset(data, 0, RTSP_SESSION_BUFF_LEN);
		headLen = (int)(pos - buff) + RTSP_END_TAG_LEN;
		memcpy(data, buff, headLen);

		if (PARSER_OK != rtsp_getBodyLength(hdr, session, data, headLen, &bodyLen))
		{
			//SCLogInfo("[RTSP]len:%d data:%s[%s:%d]", headLen, data, __func__, __LINE__);

			SCLogInfo("[RTSP]send to req, len(%d), ssid(%u)[%s:%d]", headLen, hdr->sessionid, __func__, __LINE__);
			if (0 != buffer_sendtoreq(hdr, data, headLen))
			{
				SCLogError("[RTSP]send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			buff += headLen;
			len -= headLen;
			continue;
		}

		if (0 == bodyLen)
		{
			/* Update and send this session */
			if (PARSER_OK != rtsp_handleCltRspSession(hdr, session, data, headLen))
			{
				return PARSER_ERROR;
			}

			buff += headLen;
			len -= headLen;
			continue;
		}

		if (len < (headLen + bodyLen))
		{
			if (0 != evbuffer_add(session->rspBuf, buff, len))
			{
				SCLogError("[RTSP]add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Session data all receive */
		dataLen = headLen + bodyLen;
		memset(data, 0, RTSP_SESSION_BUFF_LEN);

		memcpy(data, buff, dataLen);
		if (!strncmp(data + headLen, "RTSP", 4))
		{
			/* Update and send this session */
			if (PARSER_OK != rtsp_handleCltRspSession(hdr, session, data, headLen))
			{
				return PARSER_ERROR;
			}

			buff += headLen;
			len -= headLen;
		}
		else
		{
			/* Update and send this session */
			if (PARSER_OK != rtsp_handleCltRspSession(hdr, session, data, dataLen))
			{
				return PARSER_ERROR;
			}

			buff += dataLen;
			len -= dataLen;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtsp_handleClientRsp
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
static int rtsp_handleClientRsp(ForwardObject *obj, struct filter_header *hdr, RTSP_SESSION *session)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[RTSP]add data to session rsp buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

		}

		/* Client handle: rsp buffer and this data */
		if (PARSER_OK != rtsp_updateCltEventRspbufData(hdr, session))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Client handle: this data */
			if (PARSER_OK != rtsp_updateCltRspbufData(hdr, session, (char *)(obj->buffdata.data), (int)(obj->buffdata.len)))
			{
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server response message")

static int rtsp_updateAndSendSvrRspSession(struct filter_header *hdr, char *data, int len, char *replaceIp, char *replacePort)
{
	if (ROUTE_MAPPED == hdr->routetype)
	{
		if (PARSER_OK != rtsp_replaceIpPort(hdr, data, &len, replaceIp, replacePort))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		SCLogInfo("[RTSP]route type(%d) is not mapped, not to change response data, sessionid(%u)[%s:%d]",
			hdr->routetype, hdr->sessionid, __func__, __LINE__);
	}

	//SCLogInfo("[RTSP]len:%d data:%s[%s:%d]", len, data, __func__, __LINE__);
	SCLogInfo("[RTSP]send to req, len(%d), ssid(%u)[%s:%d]", len, hdr->sessionid, __func__, __LINE__);
	if (0 != buffer_sendtoreq(hdr, data, len))
	{
		SCLogError("[RTSP]send data to req failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtsp_handleSvrRspSession
*Action      : handle svr response session data
*Input       : hdr          packet processing header information
			   session      session obj
			   data         data
			   len          data length
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.20
*Instruction : null
************************************************************/
static int rtsp_handleSvrRspSession(struct filter_header *hdr, RTSP_SESSION *session, char *data, int len)
{
	unsigned short localPort1;
	unsigned short localPort2;
	int clientPort1;
	int clientPort2;
	char *pClientPort = NULL;
	char sipStr[PARSER_IP_BUFF_SIZE];
	char dipStr[PARSER_IP_BUFF_SIZE];
	char lipStr[PARSER_IP_BUFF_SIZE];
	char localPortStr[PARSER_COMMON_LEN];

	IP_NUM_TO_STR(hdr->ip->saddr, sipStr, PARSER_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->ip->daddr, dipStr, PARSER_IP_BUFF_SIZE);
	IP_NUM_TO_STR(hdr->localip, lipStr, PARSER_IP_BUFF_SIZE);
	SCLogInfo("[RTSP]from forward, data(%p), len(%d), sip(%s), sport(%u), dip(%s), dport(%u), lip(%s), lport(%u), ssid(%u)[%s:%d]",
		data, len, sipStr, hdr->tcp->source, dipStr, hdr->tcp->dest,
		lipStr, hdr->localport, hdr->sessionid, __func__, __LINE__);

	localPort1 = 0;
	localPort2 = 0;
	clientPort1 = 0;
	clientPort2 = 0;
	localPortStr[0] = '\0';
	pClientPort = strnstr(data, RTSP_CLIENT_PORT_KEY, len);
	if (pClientPort)
	{
		sscanf(pClientPort, "client_port=%d-%d", &clientPort1, &clientPort2);
		if ((0 != clientPort1) && (0 != clientPort2))
		{
			if (PARSER_OK != rtsp_getLocalPort(&localPort1, &localPort2))
			{
				SCLogError("[RTSP]can't find valid rtsp local port, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

			snprintf(localPortStr, PARSER_COMMON_LEN, "%u-%u", localPort1, localPort2);
			if (PARSER_OK != rtsp_createDataSvr(hdr, lipStr, sipStr,
				localPort1, (unsigned short)clientPort1,
				localPort2, (unsigned short)clientPort2))
			{
				return PARSER_ERROR;
			}
		}
		else
		{
			SCLogError("[RTSP]get rtsp client port failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		}
	}

	return rtsp_updateAndSendSvrRspSession(hdr, data, len, dipStr, localPortStr);
}

/************************************************************
*Function    : rtsp_updateSvrEventRspbufData
*Action      : check the full session in rspbuf
*Input       : hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int rtsp_updateSvrEventRspbufData(struct filter_header *hdr, RTSP_SESSION *session)
{
	int dataLen;
	ev_ssize_t ret;
	size_t eventBufLen;
	struct evbuffer_ptr pos;
	char data[RTSP_SESSION_BUFF_LEN];

	while (1)
	{
		/* Get data length of client response eventbuffer */
		eventBufLen = evbuffer_get_length(session->rspBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check session data all receive */
		pos = evbuffer_search(session->rspBuf, "\r\n\r\n", RTSP_END_TAG_LEN, NULL);
		if (-1 == pos.pos)
		{
			/* Not find, write data to fp */
			break;
		}

		/* Get session data */
		memset(data, 0, RTSP_SESSION_BUFF_LEN);
		dataLen = (int)(pos.pos) + RTSP_END_TAG_LEN;
		ret = evbuffer_remove(session->rspBuf, data, (size_t)dataLen);
		if (-1 == ret)
		{
			SCLogError("[RTSP]remove data from event buff failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return PARSER_ERROR;
		}

		/* Update and send this session */
		if (PARSER_OK != rtsp_handleSvrRspSession(hdr, session, data, dataLen))
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtsp_updateSvrRspbufData
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
static int rtsp_updateSvrRspbufData(struct filter_header *hdr, RTSP_SESSION *session, char *buff, int len)
{
	int dataLen;
	char *pos = NULL;
	char data[RTSP_SESSION_BUFF_LEN];

	while (1)
	{
		/* Get data length of client response buff */
		if (0 >= len)
		{
			break;
		}

		/* Check session data all receive */
		pos = strnstr(buff, "\r\n\r\n", len);
		if (NULL == pos)
		{
			/* Add data to eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, buff, len))
			{
				SCLogError("[RTSP]add data to session event buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}
			break;
		}

		/* Get session data */
		memset(data, 0, RTSP_SESSION_BUFF_LEN);
		dataLen = (int)(pos - buff) + RTSP_END_TAG_LEN;
		memcpy(data, buff, dataLen);
		buff += dataLen;
		len -= dataLen;

		/* Update and send this session */
		if (PARSER_OK != rtsp_handleSvrRspSession(hdr, session, data, dataLen))
		{
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : rtsp_handleServerRsp
*Action      : handle server response
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
static int rtsp_handleServerRsp(ForwardObject *obj, struct filter_header *hdr, RTSP_SESSION *session)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[RTSP]add data to session rsp buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
				return PARSER_ERROR;
			}

		}

		/* Client handle: rsp buffer and this data */
		if (PARSER_OK != rtsp_updateSvrEventRspbufData(hdr, session))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Client handle: this data */
			if (PARSER_OK != rtsp_updateSvrRspbufData(hdr, session, (char *)(obj->buffdata.data), (int)(obj->buffdata.len)))
			{
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

/************************************************************
*Function    : rtsp_data
*Action      : RTSP protocol data processing
*Input       : hdr  packet processing header information
			   ev   data packet processing type
			   buff data
			   len  data len
*Output      : null
*Return      : FLT_RET
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET rtsp_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	int isok;
	ForwardObject *obj = NULL;
	RTSP_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("[RTSP]invalid para, hdr(%p)[%s:%d]", hdr, __func__, __LINE__);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:          /* To connect server */
	{
		session = rtsp_allocSession();
		if (session == NULL)
		{
			SCLogError("[RTSP]create new rtsp session failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		session->connecting = RTSP_CONNECTING;
		SCLogInfo("[RTSP]connect in, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
		break;
	}

	case FLTEV_ONSVROK:         /* Connect to server success or failure */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[RTSP]invalid para, user(%p)[%s:%d]", hdr->user, __func__, __LINE__);
			return FLTRET_OK;
		}

		if ((NULL == buff) || ((unsigned int)sizeof(isok) != (unsigned int)len))
		{
			SCLogError("[RTSP]invalid para, buff(%p), len(%u)[%s:%d]", buff, (unsigned int)len, __func__, __LINE__);
			return FLTRET_OK;
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			/* Zero: connection failed */
			SCLogError("[RTSP]connect server failed, sock(%d), ssid(%u)[%s:%d]", isok, hdr->sessionid, __func__, __LINE__);
			return rtsp_closeSession(hdr, (int)len, "Check isock");
		}

		SCLogInfo("[RTSP]connect server success, sock(%d), ssid(%u)[%s:%d]", isok, hdr->sessionid, __func__, __LINE__);

		session = hdr->user;
		session->connecting = RTSP_CONNECTED;

		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return rtsp_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}
		break;
	}

	case FLTEV_ONSOCKDATA:          /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[RTSP]invalid para, user(%p)[%s:%d]", hdr->user, __func__, __LINE__);
			return FLTRET_OK;
		}

		session = hdr->user;

		SCLogInfo("[RTSP]on socket data, len(%d), ssid(%u)[%s:%d]", (int)len, hdr->sessionid, __func__, __LINE__);

		if (RTSP_DISCONNECT == session->connecting)
		{
			/* Has not handshake, receive data, not handle */
			SCLogWarning("[RTSP]svr not connect, not progress.... ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			return FLTRET_OK;
		}
		else if (RTSP_CONNECTING == session->connecting)
		{
			if ((NULL != buff) && (0 < len))
			{
				/* Connecting, receive data, add to req buffer, when connected and brush out */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("[RTSP]add data to session buffer failed, ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
					return rtsp_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("[RTSP]svr not ready, delay.... ssid(%u)[%s:%d]", hdr->sessionid, __func__, __LINE__);
			}
			return FLTRET_OK;
		}
		else if (RTSP_CONNECTED == session->connecting)
		{
			if (NULL != hdr->svr)
			{
				if (PARSER_OK != rtsp_handleClientReq(hdr, session, buff, len))
				{
					return rtsp_closeSession(hdr, (int)len, "Handle client request data");
				}
			}
			else
			{
				if (PARSER_OK != rtsp_handleServerReq(hdr, session, buff, len))
				{
					return rtsp_closeSession(hdr, (int)len, "Handle server request data");
				}
			}
		}
		else
		{
			/* Unknown state: not handle */
			SCLogWarning("[RTSP]invalid connetcion status(%d), ssid(%u)[%s:%d]",
				session->connecting, hdr->sessionid, __func__, __LINE__);
		}
		break;
	}

	case FLTEV_ONFWDDATA:           /* Receive data from arbitration-machine */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[RTSP]invalid para, user(%p)[%s:%d]", hdr->user, __func__, __LINE__);
			return FLTRET_OK;
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("[RTSP]invalid para, buff(%p), len(%u)[%s:%d]", buff, (unsigned int)len, __func__, __LINE__);
			return FLTRET_OK;
		}

		session = hdr->user;
		obj = (ForwardObject *)buff;

		SCLogInfo("[RTSP]receive data from fwd, len(%u), sessionid(%u)[%s:%d]",
			(unsigned int)obj->buffdata.len, hdr->sessionid, __func__, __LINE__);

		if (PARSER_OK != rtsp_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != rtsp_handleClientRsp(obj, hdr, session))
			{
				return rtsp_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != rtsp_handleServerRsp(obj, hdr, session))
			{
				return rtsp_closeSession(hdr, (int)len, "Handle server response data");
			}
		}
		break;
	}

	case FLTEV_ONSOCKERROR:         /* Close session */
	{
		return rtsp_closeSession(hdr, 0, NULL);
	}

	default:
	{
		break;
	}
	}

	return FLTRET_OK;
}

/************************************************************
*Function    : rtsp_free
*Action      : RTSP free
*Input       : null
*Output      : null
*Return      : FLT_RET
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int rtsp_free(void)
{
	return FLTRET_OK;
}

/************************************************************
*Function    : rtsp_init
*Action      : RTSP init
*Input       : null
*Output      : null
*Return      : FLT_RET
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int rtsp_init(void)
{
	unsigned int size;

	if ((1024 > g_gapcfg->port_rtsp_begin) || (g_gapcfg->port_rtsp_begin > g_gapcfg->port_rtsp_end))
	{
		SCLogError("[RTSP]invalid begin port(%u) and end port(%u), please check[%s:%d]",
			g_gapcfg->port_rtsp_begin, g_gapcfg->port_rtsp_end, __func__, __LINE__);
		return PARSER_ERROR;
	}

	g_rtspDynamicPortNum = (unsigned short)(g_gapcfg->port_rtsp_end - g_gapcfg->port_rtsp_begin + 1);
	size = ((unsigned int)g_rtspDynamicPortNum) * ((unsigned int)sizeof(RTSP_DYNAMIC_PORT));
	g_rtspDynamicPort = (RTSP_DYNAMIC_PORT *)SCMalloc(size);
	if (NULL == g_rtspDynamicPort)
	{
		g_rtspDynamicPortNum = 0;
		SCLogError("[RTSP]SCMalloc memory failed, size(%u)[%s:%d]", size, __func__, __LINE__);
		return PARSER_ERROR;
	}
	memset(g_rtspDynamicPort, 0, size);

	return FLTRET_OK;
}

/************************************************************
*Function    : rtsp_checkData
*Action      : rtsp check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : SVR_ID
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID rtsp_checkData(const void *buff, size_t len)
{
	if ((13 < len) && !memcmp(buff, "OPTIONS rtsp:", 13))
	{
		return SVR_ID_RTSP;
	}
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_rtsp
*Action      : RTSP protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static struct packet_filter g_filter_rtsp =
{
	SVR_ID_RTSP,
	"rtsp parser",
	rtsp_init,
	rtsp_data,
	rtsp_free,
	rtsp_checkData
};

PROTOCOL_FILTER_OP(rtsp)

