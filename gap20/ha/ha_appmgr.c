#include "app_common.h"
#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_statemgr.h"
#include "ha_agent.h"
#include "ha_appmgr.h"
#include "bitops.h"

static HaAppMgr* g_pHaAppMgr = NULL;

static int HaStateChangeCB(HAEvent nHaEvent, const char* pDate, int nDataLen);

struct event* appmgr_add_read(int nSocketFd, short ev, event_callback_fn cb, void* args)
{
	struct event* pReadEvent = event_new(g_pHaAppMgr->pAppEventBase, nSocketFd, ev, cb, args ? args : g_pHaAppMgr);
	if (NULL == pReadEvent)
	{
		return NULL;
	}

	event_add(pReadEvent, NULL);

	return pReadEvent;
}

struct bufferevent* appmgr_add_bev(evutil_socket_t nSocketFd, bufferevent_data_cb datacb,
	bufferevent_data_cb writecb, bufferevent_event_cb eventcb, 
	struct timeval* tv, void* args)
{
	struct bufferevent* pBufferEvent = bufferevent_socket_new(g_pHaAppMgr->pAppEventBase,
		nSocketFd,
		BEV_OPT_THREADSAFE | BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(pBufferEvent, datacb, writecb, eventcb, args);
	if (tv)
	{
		bufferevent_set_timeouts(pBufferEvent, tv, tv);
	}

	bufferevent_enable(pBufferEvent, EV_READ | EV_WRITE);

	return pBufferEvent;
}

HaAgentClient* ha_app_get(uint32_t dwAppModID)
{
	HaAgentClient* pAgentClient = NULL;
	
	pthread_rwlock_wrlock(&g_pHaAppMgr->lock);

	list_for_each_entry(pAgentClient, &g_pHaAppMgr->app_list, node)
	{
		if (pAgentClient->dwAppModID == dwAppModID)
		{
			pthread_rwlock_unlock(&g_pHaAppMgr->lock);
			return pAgentClient;
		}
	}
	pthread_rwlock_unlock(&g_pHaAppMgr->lock);

	return NULL;
}

void ha_app_add(HaAgentClient* pAgentClient)
{
	if (!pAgentClient)
	{
		return;
	}

	pthread_rwlock_wrlock(&g_pHaAppMgr->lock);
	list_add(&pAgentClient->node, &g_pHaAppMgr->app_list);
	pthread_rwlock_unlock(&g_pHaAppMgr->lock);
}

void ha_app_del(HaAgentClient* pAgentClient)
{
	bufferevent_free(pAgentClient->pBufferEvent);
	evbuffer_free(pAgentClient->pRecvBuffer);
	
	pthread_rwlock_wrlock(&g_pHaAppMgr->lock);
	list_del(&pAgentClient->node);
	pthread_rwlock_unlock(&g_pHaAppMgr->lock);
	
	SCFree(pAgentClient);
}

int ha_app_send(HaAgentClient* pAgentClient, HaAppMessage* pDate, int nDataLen)
{
	if (bufferevent_write(pAgentClient->pBufferEvent, pDate, nDataLen))
	{
		return -1;
	}

	return 0;
}

int ha_app_request_process(HaAgentClient* pAgentClient, HaAppMessage* pAppMessage, int nMsgLen)
{
	int nDataLen = 0;
	int nStbInline = 0;
	uint32_t dwAppModID;

	char chLocalIP[20] = { 0 };
	struct in_addr rLocalAddr;

	HaHost* pHaHost = NULL;
	HaAgentClient* pOldAgentClient = NULL;
	HaState nRunningState = 0;

	pAppMessage->rAppMessageHead.nType = HA_APP_MESSAGE_TYPE_RESPONE;

	switch (pAppMessage->rAppMessageHead.nAppMsgID)
	{
	case HA_APP_REGISTER:
		dwAppModID = pAppMessage->rAppMessageHead.dwAppModID;
		pOldAgentClient = ha_app_get(dwAppModID);
		nRunningState = HaGetLocalRunningState();

		HA_LOG_DEBUG("ha_app_request_process(): %d, running_state: %s\n", dwAppModID, ha_state_to_str(nRunningState));
		
		if (!pOldAgentClient) 
		{
			if (nRunningState == HA_STATE_ACT || nRunningState == HA_STATE_STB)
			{
				pAppMessage->u.nReturn = HA_ERROR_EXIST;
			}
			else
			{
				pAppMessage->u.nReturn = HA_SUCCESS;
			}
		}
		else 
		{
			pAppMessage->u.nReturn = HA_ERROR_EXIST;
			ha_app_del(pOldAgentClient);
		}
		pAgentClient->dwAppModID = dwAppModID;
		ha_app_add(pAgentClient);

		nDataLen = HA_APP_MESSAGE_HEAD_LEN + sizeof(pAppMessage->u.nReturn);
		pAppMessage->rAppMessageHead.nTotalLen = nDataLen;
		ha_app_send(pAgentClient, pAppMessage, nDataLen);

		if (pAppMessage->u.nReturn == HA_ERROR_EXIST)
		{
			/*if pOldAgentClient is not null, app has registered.
			*if pOldAgentClient is null, app has not registered, but it registered too late.
			*send GO_ACT and PEER_CONN_OK event to app*/
			if (!pOldAgentClient)
			{
				pAppMessage->u.nReturn = HA_SUCCESS;
			}

			pAppMessage->rAppMessageHead.nType = HA_APP_MESSAGE_TYPE_NOTIFY;
			pAppMessage->rAppMessageHead.nAppMsgID = HA_APP_EVENT_NOTIFY;
			nDataLen = HA_APP_MESSAGE_HEAD_LEN + sizeof(HaEventMsg);
			pAppMessage->rAppMessageHead.nTotalLen = nDataLen;

			if (nRunningState == HA_STATE_ACT) 
			{
				pAppMessage->u.rEventMsg.nHaEvent = HA_EVENT_GO_ACT;
				HA_LOG_DEBUG("tell app GO_ACT event\n");
				ha_app_send(pAgentClient, pAppMessage, nDataLen);

				int i = 2;				
				for(; i < 4; i++)		
				{
					pHaHost = &g_pHaBaseMgr->rHaHostArray[i];
					if (pHaHost->rAddr.sin_addr.s_addr == 0)
					{
						continue;
					}

					if ((pHaHost->nRunningState == HA_STATE_STB) && (pHaHost->nOnTime > 0)
						&& (pHaHost->nConnectType == 2))
					{
						nStbInline = 1;
						break;
					}
				}

				if (nStbInline)
				{
					pAppMessage->u.rEventMsg.nHaEvent = HA_EVENT_PEER_CONN_OK;
					ha_app_send(pAgentClient, pAppMessage, nDataLen);
				}
			}
			else if (nRunningState == HA_STATE_STB) 
			{
				rLocalAddr.s_addr = HaGetLocalIP();
				inet_ntop(AF_INET, &rLocalAddr, chLocalIP, 20);

				pAppMessage->u.rEventMsg.nHaEvent = HA_EVENT_GO_STB;
				memcpy(pAppMessage->u.rEventMsg.chData, chLocalIP, strlen(chLocalIP) + 1);
				nDataLen += (strlen(chLocalIP) + 1);
				pAppMessage->rAppMessageHead.nTotalLen = nDataLen;
				ha_app_send(pAgentClient, pAppMessage, nDataLen);
			}
		}
		break;

	case HA_APP_UNREGISTER:
		dwAppModID = pAppMessage->rAppMessageHead.dwAppModID;

		if (pAgentClient->dwAppModID == dwAppModID)
		{
			pAppMessage->u.nReturn = HA_SUCCESS;
			list_del(&pAgentClient->node);
		}
		else
		{
			pAppMessage->u.nReturn = HA_ERROR_NOEXIST;
		}

		nDataLen = HA_APP_MESSAGE_HEAD_LEN + sizeof(pAppMessage->u.nReturn);
		pAppMessage->rAppMessageHead.nTotalLen = nDataLen;
		ha_app_send(pAgentClient, pAppMessage, nDataLen);

		/* delete app node */
		ha_app_del(pAgentClient);
		break;

	case HA_APP_DATA_SYNC:
		/* send all data to STB */
		HA_LOG_DEBUG("sync data len %d\n", nMsgLen);
		pAppMessage->u.nReturn = HaSendDataToStb((char*)pAppMessage, nMsgLen);
		//pAppMessage->u.nReturn = HA_SUCCESS;
		nDataLen = HA_APP_MESSAGE_HEAD_LEN + sizeof(pAppMessage->u.nReturn);
		pAppMessage->rAppMessageHead.nTotalLen = nDataLen;
		ha_app_send(pAgentClient, pAppMessage, nDataLen);
		HA_LOG_DEBUG("sync return\n");
		break;

	default:
		pAppMessage->u.nReturn = HA_ERROR_ERROR;
		nDataLen = HA_APP_MESSAGE_HEAD_LEN + sizeof(pAppMessage->u.nReturn);
		pAppMessage->rAppMessageHead.nTotalLen = nDataLen;
		ha_app_send(pAgentClient, pAppMessage, nDataLen);
		break;
	}

	return nDataLen;
}

void ha_app_recv(char* buff, size_t nDataLen, void* args)
{
	HaAppMessage rAppMessage;
	 
	uint32_t nTotalLen = 0;
	HaAgentClient* pAgentClient = (HaAgentClient*)args;
	HaAppMessageHead rAppMessageHead;

	evbuffer_add(pAgentClient->pRecvBuffer, buff, nDataLen);
	while (1)
	{
		if (evbuffer_copyout(pAgentClient->pRecvBuffer, &rAppMessageHead, sizeof(rAppMessageHead)) != sizeof(rAppMessageHead))
		{
			return;
		}

		nTotalLen = evbuffer_get_length(pAgentClient->pRecvBuffer);
		if (nTotalLen < rAppMessageHead.nTotalLen)
		{
			return;
		}

		evbuffer_remove(pAgentClient->pRecvBuffer, &rAppMessage, rAppMessageHead.nTotalLen);

		if (rAppMessage.rAppMessageHead.nType == HA_APP_MESSAGE_TYPE_REQUEST)
		{
			ha_app_request_process(pAgentClient, &rAppMessage, rAppMessage.rAppMessageHead.nTotalLen);
		}
	}
}

static void ha_app_ondata(struct bufferevent* pBufferEvent, void* args)
{
	size_t n = 0;
	char buff[10240];
	while (1)
	{
		n = bufferevent_read(pBufferEvent, buff, sizeof(buff));
		if (n == 0)
		{
			break;
		}
		ha_app_recv(buff, n, args);
	}

	return;
}

void ha_app_onerror(struct bufferevent* pBufferEvent, short what, void *args)
{
	HA_LOG_DEBUG("\n");
}

/**appmgr listen for app to connect*/
void ha_app_mgr_listern(int nSocketFd, short ievent, void* arg)
{	
	struct sockaddr_un rAddr;
	int nLength = sizeof(rAddr);
	
	int nClientFd = accept(nSocketFd, (struct sockaddr*)&rAddr, (socklen_t*)&nLength);
	if (nClientFd == -1)
	{
		return;
	}

	HaAgentClient* pAgentClient = (HaAgentClient*)SCMalloc(sizeof(HaAgentClient));
	pAgentClient->dwAppModID = 0;
	pAgentClient->nSocketFd = nClientFd;
	pAgentClient->pRecvBuffer = evbuffer_new();
	pAgentClient->pBufferEvent = appmgr_add_bev(nClientFd, ha_app_ondata, NULL, ha_app_onerror, NULL, pAgentClient);
}

int ha_create_unix_socket(char* pPath)
{	
	/* First of all, unlink existing socket */
	unlink(pPath);

	/* Set umask */
	mode_t old_mask = umask(0007);

	/* Make UNIX domain socket. */
	int nSocketFd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (nSocketFd < 0)
	{
		HA_LOG_ERROR("Cannot create unix stream socket: %s", strerror(errno));
		return -1;
	}

	/*make reuse*/
	int on = 1;
	setsockopt(nSocketFd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));

	/* Make server socket. */
	struct sockaddr_un serv;
	memset(&serv, 0, sizeof(struct sockaddr_un));

	serv.sun_family = AF_UNIX;
	strncpy(serv.sun_path, pPath, strlen(pPath));
	int nLength = sizeof(serv.sun_family) + strlen(serv.sun_path);

	int nReturn = bind(nSocketFd, (struct sockaddr*)&serv, nLength);
	if (nReturn < 0)
	{
		HA_LOG_ERROR("Cannot bind path %s: %s", pPath, strerror(errno));
		close(nSocketFd);	/* Avoid sd leak. */
		return -1;
	}

	nReturn = listen(nSocketFd, 5);
	if (nReturn < 0)
	{
		HA_LOG_ERROR("listen(fd %d) failed: %s", nSocketFd, strerror(errno));
		close(nSocketFd);	/* Avoid sd leak. */
		return -1;
	}

	umask(old_mask);

	return nSocketFd;
}

void* ha_app_thread(void* pArg)
{
	HaAppMgr* pMgr = (HaAppMgr*)pArg;

	HA_LOG_DEBUG("ha_appmgr running\n");
	event_base_loop(pMgr->pAppEventBase, 0);
	HA_LOG_DEBUG("loopthread return\n");
	
	return NULL;
}

int ha_app_mgr_init()
{
	if (g_pHaAppMgr)
	{
		return HA_SUCCESS;
	}

	/* alloce memory for HA application manager */
	g_pHaAppMgr = (HaAppMgr*)SCMalloc(sizeof(HaAppMgr));
	if (!g_pHaAppMgr)
	{
		HA_LOG_ERROR("memory alloc for HA application manager fail.\n");
		return HA_ERROR_NOMEM;
	}

	g_pHaAppMgr->nSocketFd = ha_create_unix_socket(HA_APP_MGR_PATH);
	if (g_pHaAppMgr->nSocketFd < 0)
	{
		goto FAIL1;
	}

	/* add ha_app_mgr->nSocketFd to recv list */
	struct event_config* cfg = event_config_new();
	event_config_require_features(cfg, EV_FEATURE_FDS);
	g_pHaAppMgr->pAppEventBase = event_base_new_with_config(cfg);
	event_config_free(cfg);

	g_pHaAppMgr->pRecvEvent = appmgr_add_read(g_pHaAppMgr->nSocketFd,
		EV_READ | EV_PERSIST, ha_app_mgr_listern, NULL);

	pthread_rwlock_init(&g_pHaAppMgr->lock, NULL);
	INIT_LIST_HEAD(&g_pHaAppMgr->app_list);

	pthread_create(&g_pHaAppMgr->evthread, NULL, ha_app_thread, g_pHaAppMgr);

	HaStateNotifyRegister(HaStateChangeCB);
	
	return HA_SUCCESS;

	close(g_pHaAppMgr->nSocketFd);
	
FAIL1:
	SCFree(g_pHaAppMgr);
	g_pHaAppMgr = NULL;
	
	return HA_ERROR_ERROR;
}

int ha_app_send_event(HAEvent nHaEvent, const char* pDate, int nDataLen)
{		
	HaAppMessage rAppMessage;
	memset(&rAppMessage, 0, sizeof(rAppMessage));

	int nMsgLen = HA_APP_MESSAGE_HEAD_LEN + sizeof(HAEvent) + nDataLen;

	rAppMessage.rAppMessageHead.nType = HA_APP_MESSAGE_TYPE_NOTIFY;
	rAppMessage.rAppMessageHead.nAppMsgID = HA_APP_EVENT_NOTIFY;	
	rAppMessage.rAppMessageHead.nTotalLen = nMsgLen;

	rAppMessage.u.rEventMsg.nHaEvent = nHaEvent;
	memcpy(rAppMessage.u.rEventMsg.chData, pDate, nDataLen);
	
	HaAgentClient* pAgentClient = NULL;
	HaAppMgr* pHaAppMgr = g_pHaAppMgr;

	pthread_rwlock_wrlock(&pHaAppMgr->lock);
	list_for_each_entry(pAgentClient, &pHaAppMgr->app_list, node)
	{
		HA_LOG_DEBUG("ha_app_send_event(): app_mod_id: 0x%x, ip: %s\n", pAgentClient->dwAppModID, rAppMessage.u.rEventMsg.chData);
		rAppMessage.rAppMessageHead.dwAppModID = pAgentClient->dwAppModID;
		ha_app_send(pAgentClient, &rAppMessage, nMsgLen);
	}
	pthread_rwlock_unlock(&pHaAppMgr->lock);

	return 0;
}

static int HaStateChangeCB(HAEvent nHaEvent, const char* pDate, int nDataLen)
{
	char chStbIP[20] = { 0 };
	
	if (nHaEvent == HA_EVENT_STB_UP || nHaEvent == HA_EVENT_STB_DOWN)
	{
		//通知应用模块备机上、下线
		HaHost* pHaHost = (HaHost*)pDate;
		inet_ntop(AF_INET, (void*)&pHaHost->rAddr.sin_addr, chStbIP, 20);
		pDate = chStbIP;
		nDataLen = strlen(chStbIP) + 1;
	}
	
	//当主备机HA状态变化时通知网闸应用程序作相应处理
	return ha_app_send_event(nHaEvent, pDate, nDataLen);
}