#include "app_common.h"
#include "util-lock.h"
#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_appmgr.h"
#include "ha_agent.h"
#include "ha_statemgr.h"

struct HaSyncServer g_rSyncServer;
int HaSyncServerInit();

void HaAppClientError(struct bufferevent* pBufferEvent, short nWhat, void* pArg)
{
	HA_LOG_DEBUG("HaAppClientError****************\n");

	HaHost* pHost = (HaHost*)pArg;
	if (pHost->pBufferEvent)
	{
		bufferevent_free(pHost->pBufferEvent);
		pHost->pBufferEvent = NULL;
		
		closesocket(pHost->nSyncFd);
		pHost->nSyncFd = -1;
	}

	if (pHost->pRecvBuffer)
	{
		evbuffer_free(pHost->pRecvBuffer);
		pHost->pRecvBuffer = NULL;
	}
}

void HaAppServerError(struct bufferevent* pBufferEvent, short nWhat, void* pArg)
{
	HA_LOG_DEBUG("HaAppServerError****************\n");

	struct HaSyncServer* pSyncServer = (struct HaSyncServer*)pArg;
	if (pSyncServer->pBufferEvent)
	{
		bufferevent_free(pSyncServer->pBufferEvent);
		pSyncServer->pBufferEvent = NULL;
		
		closesocket(pSyncServer->nSyncFd);
		pSyncServer->nSyncFd = -1;
	}
	if (pSyncServer->pRecvBuffer)
	{
		evbuffer_free(pSyncServer->pRecvBuffer);
		pSyncServer->pRecvBuffer = NULL;
	}
}

struct bufferevent* syncmgr_add_bev(evutil_socket_t nSocketFd, bufferevent_data_cb readdatacb,
	bufferevent_data_cb writecb, bufferevent_event_cb eventcb, 
	struct timeval* tv, void* pArg)
{
	struct bufferevent* pBufferEvent = bufferevent_socket_new(g_rSyncServer.pSyncEventBase, nSocketFd, BEV_OPT_CLOSE_ON_FREE);
	
	bufferevent_setcb(pBufferEvent, readdatacb, writecb, eventcb, pArg);
	if (tv)
	{
		bufferevent_set_timeouts(pBufferEvent, tv, tv);
	}
		
	bufferevent_enable(pBufferEvent, EV_READ | EV_WRITE);
	
	return pBufferEvent;
}

void HaSyncClientProcessReadData(char* buff, size_t nDataLen, void* pArg)
{
	uint32_t nTotalLen = 0;
	HaAgentClient* pAgentClient = NULL;
	HaHost* pHaHost = (HaHost*)pArg;
	HaAppMessage rAppMessage;
	HaAppMessageHead* pAppMessageHead = &rAppMessage.rAppMessageHead;
	
	HA_LOG_DEBUG("in \n");

	evbuffer_add(pHaHost->pRecvBuffer, buff, nDataLen);

	while (1)
	{
		if (evbuffer_copyout(pHaHost->pRecvBuffer, pAppMessageHead, sizeof(*pAppMessageHead)) != sizeof(*pAppMessageHead))
		{
			return;
		}
			
		nTotalLen = evbuffer_get_length(pHaHost->pRecvBuffer);
		if (nTotalLen < pAppMessageHead->nTotalLen)
		{
			return;
		}

		evbuffer_remove(pHaHost->pRecvBuffer, &rAppMessage, pAppMessageHead->nTotalLen);

		pAgentClient = ha_app_get(pAppMessageHead->dwAppModID);
		if (NULL == pAgentClient)
		{
			return;
		}
		
		pAppMessageHead->nType = HA_APP_MESSAGE_TYPE_NOTIFY;
		ha_app_send(pAgentClient, &rAppMessage, pAppMessageHead->nTotalLen);
	}
}

/**sync data from stb host on*/
void HaSyncConData(struct bufferevent* pBufferEvent, void* pArg)
{
	size_t nRead = 0;
	char chBuffer[10240] = { 0 };

	while (1)
	{
		nRead = bufferevent_read(pBufferEvent, chBuffer, sizeof(chBuffer));
		HA_LOG_DEBUG("LENGTH = %d\n", nRead);
		
		if (nRead == 0)
		{
			break;
		}

		HaSyncClientProcessReadData(chBuffer, nRead, pArg);
	}
	
	return;
}

void HaSyncServerProcessReadData(char* buff, size_t nDataLen, void* pArg)
{
	HA_LOG_DEBUG("HaSyncServerProcessReadData start!\n");
	
	uint32_t nTotal = 0;
	HaAgentClient* pAgentClient = NULL;
	
	HaAppMessage rRecvMsg;
	HaAppMessageHead* pAppMessageHead = &rRecvMsg.rAppMessageHead;
	struct HaSyncServer* pSyncServer = (struct HaSyncServer*)pArg;
	
	evbuffer_add(pSyncServer->pRecvBuffer, buff, nDataLen);
	while (1)
	{
		if (evbuffer_copyout(pSyncServer->pRecvBuffer, pAppMessageHead, sizeof(*pAppMessageHead)) != sizeof(*pAppMessageHead))
		{
			return;
		}
			
		nTotal = evbuffer_get_length(pSyncServer->pRecvBuffer);
		if (nTotal < pAppMessageHead->nTotalLen)
		{
			return;
		}
			
		evbuffer_remove(pSyncServer->pRecvBuffer, &rRecvMsg, pAppMessageHead->nTotalLen);

		pAgentClient = ha_app_get(pAppMessageHead->dwAppModID);
		if (NULL == pAgentClient)
		{
			return;
		}
			
		pAppMessageHead->nType = HA_APP_MESSAGE_TYPE_NOTIFY;
		ha_app_send(pAgentClient, &rRecvMsg, pAppMessageHead->nTotalLen);
	}
}

/**sync data from act host on*/
void HaSyncReadData(struct bufferevent* pBufferEvent, void* pArg)
{
	size_t nRead = 0;
	char chBuffer[10240] = { 0 };

	while (1)
	{
		size_t nReadn = bufferevent_read(pBufferEvent, chBuffer, sizeof(chBuffer));
		if (nRead == 0)
		{
			break;
		}
			
		HaSyncServerProcessReadData(chBuffer, nRead, pArg);
	}
	
	return;
}

void HaSyncAccept(int nSocketFd, short ievent, void* pArg)
{
	struct sockaddr_in sin;
	socklen_t nLen = sizeof(sin);
	struct HaSyncServer* pSyncServer = (struct HaSyncServer*)pArg;

	int nClientFd = accept(nSocketFd, &sin, &nLen);
	if (nClientFd < 0)
	{
		HA_LOG_ERROR("accept fail.\n");
		return;
	}

	HA_LOG_DEBUG("accept from %s:%d \n", inet_ntoa(sin.sin_addr), sin.sin_port);

	g_rSyncServer.nSyncFd = nClientFd;
	g_rSyncServer.pRecvBuffer = evbuffer_new();
	
	g_rSyncServer.pBufferEvent = syncmgr_add_bev(nClientFd, HaSyncReadData,
		NULL, HaAppServerError, NULL, &g_rSyncServer);
}

int HaSyncConnect(HaHost* pHost)
{
	HA_LOG_DEBUG("HaSyncConnect in \n");

	if (pHost->nSyncFd > 0)
	{
		HA_LOG_DEBUG("sync channel has connected\n");
		return HA_SUCCESS;
	}

	int nSocketFd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in rAddr;
	rAddr.sin_family = AF_INET;
	rAddr.sin_port = htons(ntohs(pHost->rAddr.sin_port) + 1);
	rAddr.sin_addr.s_addr = pHost->rAddr.sin_addr.s_addr;
	
	if (connect(nSocketFd, &rAddr, sizeof(rAddr)) < 0)
	{
		HA_LOG_ERROR("connect host fail(%s).\n", strerror(errno));
		return -HA_ERROR_ERROR;
	}
	HA_LOG_DEBUG("connected to %s\n", inet_ntoa(pHost->rAddr.sin_addr));
	
	pHost->nSyncFd = nSocketFd;
	pHost->pRecvBuffer = evbuffer_new();
	pHost->pBufferEvent = syncmgr_add_bev(nSocketFd, HaSyncConData,
		NULL, HaAppClientError, NULL, pHost);
	
	return HA_SUCCESS;
}

int HaSyncDisconnect(HaHost* pHost)
{
	HA_LOG_DEBUG("in \n");

	if (!pHost)
	{
		return 0;
	}
		
	HaAppClientError(NULL, 0, pHost);
	
	return HA_SUCCESS;
}

void HaCloseSyncSocket()
{
	int i = 0;
	HaHost* pHost = NULL;
	HaHost* pNext = NULL;

	for (; i < 4; i++)
	{
		pHost = &g_pHaBaseMgr->rHaHostArray[i];
		if (pHost->pBufferEvent)
		{
			HA_LOG_DEBUG("FREE bufferevent, host %s\n", inet_ntoa(pHost->rAddr.sin_addr));
			bufferevent_free(pHost->pBufferEvent);
			pHost->pBufferEvent = NULL;
			pHost->nSyncFd = 0;
		}

		if (pHost->pRecvBuffer)
		{
			evbuffer_free(pHost->pRecvBuffer);
			pHost->pRecvBuffer = NULL;
		}
	}
}

//当主备状态改变时对同步连接套接字进行相应处理
static int HaStateChangeCB(HAEvent nHaEvent, const char* pData, int nDataLen)
{
	int nReturn = HA_SUCCESS;

	HA_LOG_DEBUG("ha_syncmgr_ha_state_change_cb: %s\n", ha_event_to_str(nHaEvent));

	if (nHaEvent == HA_EVENT_STB_UP) 
	{
		//备机上线，连接备机，并向应用程序发送备机连接结果消息
		nReturn = HaSyncConnect((HaHost*)pData);
		if (nReturn == HA_SUCCESS)
		{
			ha_app_send_event(HA_EVENT_PEER_CONN_OK, NULL, 0);
		}
		else
		{
			HA_LOG_ERROR("connect STB fail.\n");
			ha_app_send_event(HA_EVENT_PEER_CONN_FAIL, NULL, 0);
		}
	}
	else if (nHaEvent == HA_EVENT_STB_DOWN) 
	{
		////备机下线，断开与备机的连接
		nReturn = HaSyncDisconnect((HaHost*)pData);
	}
	else if (nHaEvent == HA_EVENT_GO_OOS)
	{
		//OOS状态，断开同步连接套接字
		HaCloseSyncSocket();
	}
	else if (nHaEvent == HA_EVENT_CONF_CLOSE_SOCKET) 
	{
		//设备主备机配置信息，断开同步连接套接字，反初始化
		HaCloseSyncSocket();
		ha_sync_mgr_deinit();
	}
	else if (nHaEvent == HA_EVENT_CONF_RECOVER) 
	{
		//重新进行初始化
		nReturn = HaSyncServerInit();
	}

	return nReturn;
}

int ha_init_sync_socket()
{
	int nSocketFd = socket(AF_INET, SOCK_STREAM, 0);
	if (nSocketFd < 0)
	{
		HA_LOG_ERROR("create data sync channel socket fail.\n");
		return -HA_ERROR_ERROR;
	}

	int on = 1;
	setsockopt(nSocketFd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, sizeof(on));
	setsockopt(nSocketFd, SOL_SOCKET, SO_REUSEPORT, (const void*)&on, sizeof(on));
	
	int sync_port = HaGetLocalPort() + 1;

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = HaGetLocalIP();
	sin.sin_port = htons(sync_port);
	
	HA_LOG_DEBUG("ip: %s, port: %d\n", inet_ntoa(sin.sin_addr), sync_port);
	
	if (bind(nSocketFd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
	{
		HA_LOG_ERROR("bind fail(%s).\n", strerror(errno));
	}
		
	listen(nSocketFd, 5);
	
	return nSocketFd;
}

int HaSyncServerInit()
{
	HA_LOG_DEBUG("HaSyncServerInit start!\n");
	
	/* init data sync channel */
	g_rSyncServer.nServerSockFd = ha_init_sync_socket();
	if (g_rSyncServer.nServerSockFd < 0)
	{
		return -HA_ERROR_ERROR;
	}
		
	g_rSyncServer.pAcceptEvent = appmgr_add_read(g_rSyncServer.nServerSockFd,
		EV_READ | EV_PERSIST, HaSyncAccept, &g_rSyncServer);

	return HA_SUCCESS;
}

void HaSyncBackground(evutil_socket_t nSocketFd, short nFlag, void* pParam)
{
}

void* HaSyncLoopThread(void* pArg)
{	
	struct event_base* pSyncEventBase = (struct event_base*)pArg;
		
	HA_LOG_DEBUG("ha_syncmgr running\n");
	int nReturn = event_base_loop(pSyncEventBase, 0);
	HA_LOG_ERROR("loopthread return %d\n", nReturn);
	
	return NULL;
}

int ha_sync_mgr_init()
{		
	g_rSyncServer.pSyncEventBase = event_base_new();
	g_rSyncServer.pBackgroudEvent = event_new(g_rSyncServer.pSyncEventBase,
		-1,
		EV_READ | EV_PERSIST,
		HaSyncBackground, NULL);
	
	struct timeval tvTime = { LIBEVENT_DEFAULT_TIMER, 0 };
	event_add(g_rSyncServer.pBackgroudEvent, &tvTime);
	
	pthread_t pthread;
	pthread_create(&pthread, NULL, HaSyncLoopThread, g_rSyncServer.pSyncEventBase);

	if (HaSyncServerInit() < 0)
	{
		return -1;
	}		

	HaStateNotifyRegister(HaStateChangeCB);
	
	return HA_SUCCESS;
}

void ha_sync_mgr_deinit()
{
	HaAppServerError(NULL, 0, &g_rSyncServer);
	
	if (g_rSyncServer.pAcceptEvent)
	{
		event_del(g_rSyncServer.pAcceptEvent);
		event_free(g_rSyncServer.pAcceptEvent);
		g_rSyncServer.pAcceptEvent = NULL;
		
		closesocket(g_rSyncServer.nServerSockFd);
	}
}