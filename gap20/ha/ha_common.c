#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "util-lock.h"
#include "bitops.h"
#include "app_common.h"
#include "cmd_common.h"

#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"

HaHost g_rBcastHost;
HaBaseMgr* g_pHaBaseMgr;

HaPacketHooks* g_pHooks[HA_PAYLOAD_MAX] = {};
HaPendingList  g_rResponse[HA_PAYLOAD_MAX] = {};

int HaStateCommonChangeCB(HAEvent nHaEvent, const char *pData, int nDataLen);

static uint32_t hashlist_response_hash(HashListTable* tb, void* ptr, uint16_t aa)
{
	HaPendingObj* pHaPendingObj = (HaPendingObj*)ptr;
	return ((uint32_t)pHaPendingObj->pHaPktObj->nSequence % tb->array_size);
}

static char hashlist_response_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	HaPendingObj* pobj1 = (HaPendingObj*)p1;
	HaPendingObj* pobj2 = (HaPendingObj*)p1;
	
	return (pobj1->pHaPktObj->nSequence == pobj2->pHaPktObj->nSequence);
}

static void hashlist_response_onfree(void *ptr)
{
}

int ha_pkt_hooks_reg(HaPacketHooks* pHooks)
{
	if (pHooks == NULL)
	{
		return -1;
	}
		
	if (g_pHooks[pHooks->nID] != NULL)
	{
		return -1;
	}
	
	g_pHooks[pHooks->nID] = pHooks;
	
	return 0;
}

int ha_response_hash_init()
{
	int i = 0;
	for (; i < HA_PAYLOAD_MAX; i++)
	{
		pthread_mutex_init(&g_rResponse[i].ht_mutex, NULL);
		g_rResponse[i].pHashTable = HashListTableInit(1024, hashlist_response_hash, hashlist_response_compare,
			hashlist_response_onfree);
		if (g_rResponse[i].pHashTable == NULL)
		{
			break;
		}			
	}
	
	if (i < HA_PAYLOAD_MAX)
	{
		while (--i >= 0)
		{
			HashListTableFree(g_rResponse[i].pHashTable);
			g_rResponse[i].pHashTable = NULL;
		}
		return -1;
	}
	
	return 0;
}

//调用请求应答包的超时处理函数
static void HaResponseTimeout(evutil_socket_t nSocketFd, short ev, void* pArg)
{
	if (pArg == NULL)
	{
		return;
	}

	HaPendingObj* pHaPendingObj = (HaPendingObj*)(pArg);
	event_free(pHaPendingObj->pTimerEvent);
	HaPendingList* pHaPendingList = &g_rResponse[pHaPendingObj->pHaPktObj->nPaLoadType];

	pthread_mutex_lock(&pHaPendingList->ht_mutex);
	HashListTableRemove(pHaPendingList->pHashTable, pHaPendingObj, sizeof(pHaPendingObj));
	pthread_mutex_unlock(&pHaPendingList->ht_mutex);

	if (g_pHooks[pHaPendingObj->pHaPktObj->nPaLoadType]->LocalTimeoutCB)
	{
		g_pHooks[pHaPendingObj->pHaPktObj->nPaLoadType]->LocalTimeoutCB(pHaPendingObj->pHaPktObj, pHaPendingObj->pHaHost);
	}
		
	SCFree(pHaPendingObj->pHaPktObj);
	SCFree(pHaPendingObj);
}

/***send data via udp socket*pBuffer:*/
int HaManagerSendData(HaPacketType nReqRespType, HaPaloadType nPaLoadType, uint32_t nSequence, uint8_t* pBuffer, int nLength, HaHost* pHaHost)
{
	size_t nDateLen = sizeof(HaPktObject) + nLength;
	HaPktObject* pHaPktObj = SCMalloc(nDateLen);
	if (pHaPktObj == NULL)
	{
		return -1;
	}	
	
	int nAuthMode = HaGetAuthMode();
	
	pHaPktObj->nVersion = RONGAN_HA_VERSION;
	pHaPktObj->nAuthMode = nAuthMode;
	pHaPktObj->nReqRespType = nReqRespType;
	pHaPktObj->nPaLoadType = nPaLoadType;
	pHaPktObj->nSequence = nSequence;
	pHaPktObj->nDataLen = nLength;
	memcpy(pHaPktObj->chData, pBuffer, nLength);

	switch (nAuthMode)
	{
	case HA_AUTH_NONE:
		break;
	case HA_AUTH_CHECKSUM:
	case HA_AUTH_MD5:
	case HA_AUTH_SHA:
	default:
		SCFree(pHaPktObj);
		HA_LOG_ERROR("unkown auth type %d\n", nAuthMode);
		return -1;
	}

	int nReturn = 0;
	struct sockaddr_in* rAddr = &pHaHost->rAddr;
	
	if (nPaLoadType != HA_PAYLOAD_HEARTBEAT)
	{
		HA_LOG_DEBUG("send %s %s to %s\n", ha_pkt_type(pHaPktObj->nReqRespType),
			ha_payload_type(pHaPktObj->nPaLoadType), inet_ntoa(rAddr->sin_addr));
	}
	
	int nWriteLen = sendto(g_pHaBaseMgr->nUdpSockFd, pHaPktObj, nDateLen, 0,
		(struct sockaddr*)rAddr, sizeof(struct sockaddr_in));
	if (nWriteLen < 0)
	{
		HA_LOG_ERROR("sendto host %s error: %s(errno: %d)\n", inet_ntoa(rAddr->sin_addr), strerror(errno), errno);
		//g_pHooks[pHaPktObj->nPaLoadType]->SendToErrCB(pHaHost);
				
		nReturn = -1;

		ReInitUdpSocket();

		SCFree(pHaPktObj);

		return nReturn;
	}
	
	if (nPaLoadType == HA_PAYLOAD_ELECTION)
	{
		HA_LOG_DEBUG("--------------^_^--------------");
		HA_LOG_DEBUG("*********************************");
		HA_LOG_DEBUG("send election %s, sequence: %d", !nReqRespType ? "request" : "response", nSequence);
		HA_LOG_DEBUG("*********************************\n");
	}
	else if(nPaLoadType == HA_PAYLOAD_CONFIGURE)
	{
		HA_LOG_DEBUG("************************************************");
		HA_LOG_DEBUG("send conf %s to host %s, sequence: %d", !nReqRespType ? "request" : "response", inet_ntoa(rAddr->sin_addr), nSequence);
		HA_LOG_DEBUG("************************************************\n");
	}	

	/*if send request packet, hang request to pendinglist and waiting for response*/
	if (nReqRespType == HA_PACKET_REQ && !nReturn)
	{
		//if (nPaLoadType == HA_PAYLOAD_ELECTION)
		if(g_pHooks[pHaPktObj->nPaLoadType]->LocalTimeoutCB)//是否需要对应答包做超时处理
		{
			if (g_pHaBaseMgr->pHaEventBase == NULL)
			{
				HA_LOG_DEBUG("********************g_pHaBaseMgr->pHaEventBase == NULL****************************");
			}

			//发送请求数据包成功，将请求数据包保存到相应类型数据包的哈希表中，设置等待接收到应答包的超时时间
			//如果时间到，将请求数据包从哈希表中删除，并调用相应的超时处理函数
			uint32_t nTime = g_pHooks[pHaPktObj->nPaLoadType]->WaitTimeValCB();  //return ms

			struct timeval tv;
			tv.tv_sec = nTime / 1000;
			tv.tv_usec = (nTime % 1000) * 1000;

			HaPendingObj* pHaPendingObj = SCMalloc(sizeof(HaPendingObj));
			if (pHaPendingObj == NULL)
			{
				SCFree(pHaPktObj);
				return -1;
			}
			memset(pHaPendingObj, 0, sizeof(HaPendingObj));

			/* get parameter for heartbeat timeoutcb */
			pHaPendingObj->pHaHost = pHaHost;
			pHaPendingObj->pHaPktObj = pHaPktObj;

			/* set election response timer, if timeout, will run as ACT */
			pHaPendingObj->pTimerEvent = event_new(g_pHaBaseMgr->pHaEventBase, -1, EV_READ, HaResponseTimeout, pHaPendingObj);
			if (pHaPendingObj->pTimerEvent != NULL)
			{
				event_add(pHaPendingObj->pTimerEvent, &tv);

				HaPendingList* pHaPendingList = &g_rResponse[pHaPktObj->nPaLoadType];

				pthread_mutex_lock(&pHaPendingList->ht_mutex);
				HashListTableAdd(pHaPendingList->pHashTable, pHaPendingObj, sizeof(pHaPendingObj));
				pthread_mutex_unlock(&pHaPendingList->ht_mutex);

				return 0;
			}
		}
	}

	SCFree(pHaPktObj);
	
	return nReturn;
}

static void HaManagerOnDate(int nSockFd, short nEvent, void* pArg)
{
	HaBaseMgr* pHaBaseMgr = (HaBaseMgr*)pArg;
	
	struct sockaddr_in rAddr;
	int nAddrLen = sizeof(rAddr);
	uint8_t chBuffer[2048] = { 0 };

	int nReadSize = recvfrom(nSockFd, chBuffer, sizeof(chBuffer), 0, (struct sockaddr*)&rAddr, (socklen_t*)&nAddrLen);
	if (nReadSize < 0)
	{
		HA_LOG_ERROR("rcvfrom error: %s(errno: %d)\n", strerror(errno), errno);
		return;
	}
	else if (nReadSize == 0)
	{
		//网络断开
		return;
	}

	if (rAddr.sin_addr.s_addr == HaGetLocalIP()) 
	{
		//HA_LOG_DEBUG("drop bcast packet from myself.\n");
		return;
	}
	
	//更新最近一次接收到数据的时间
	pHaBaseMgr->nTime = time(NULL);
	if (!g_pHaBaseMgr->bConnected)
	{
		g_pHaBaseMgr->bConnected = TRUE;
	}

	HaPktObject* pHaPktObj = (HaPktObject*)chBuffer;

	if (pHaPktObj->nReqRespType > HA_PACKET_RESP || pHaPktObj->nPaLoadType >= HA_PAYLOAD_MAX)
	{
		HA_LOG_ERROR("received packet data error\n");
		return;
	}

	/*HA_LOG_DEBUG("recv %s %s from %s\n", ha_pkt_type(pHaPktObj->nReqRespType),
		ha_payload_type(pHaPktObj->nPaLoadType), inet_ntoa(rAddr.sin_addr));*/

	int nPeerRunningState = 0;
	int nPeerPriority = 0;

	if (pHaPktObj->nPaLoadType == HA_PAYLOAD_ELECTION)
	{
		HA_LOG_DEBUG("*********************************");
		HA_LOG_DEBUG("recv election %s, sequence: %d", !pHaPktObj->nReqRespType ? "request" : "response", pHaPktObj->nSequence);
		HA_LOG_DEBUG("*********************************\n");

		nPeerRunningState = ((struct ElectionPkt*)pHaPktObj->chData)->nMyState;
		nPeerPriority = ((struct ElectionPkt*)pHaPktObj->chData)->nMyPriority;
	}
	else if (pHaPktObj->nPaLoadType == HA_PAYLOAD_CONFIGURE)
	{
		HA_LOG_DEBUG("************************************************");
		HA_LOG_DEBUG("recv conf %s from host %s, sequence: %d", !pHaPktObj->nReqRespType ? "request" : "response", inet_ntoa(rAddr.sin_addr), pHaPktObj->nSequence);
		HA_LOG_DEBUG("************************************************\n");
	}
	else if (pHaPktObj->nPaLoadType == HA_PAYLOAD_HEARTBEAT)
	{
		nPeerRunningState = ((struct HeartBeatPkt*)pHaPktObj->chData)->nMyState;
		nPeerPriority = ((struct HeartBeatPkt*)pHaPktObj->chData)->nMyPriority;
	}
	
	int nHostType = 0;
	if (g_nBoardType == BOARDTYPE_IN)
	{
		nHostType = 3; //对端内端机
	}
	else
	{
		nHostType = 4;	//对端外端机
	}
		
	//根据对端主机类型获取主机数据保存地址
	HaHost* pHaHost = &pHaBaseMgr->rHaHostArray[nHostType - 1];
	if (pHaHost->rAddr.sin_addr.s_addr != rAddr.sin_addr.s_addr)
	{
		//主机不存在
		memset(pHaHost, 0, sizeof(HaHost));

		pHaHost->nRunningState = nPeerRunningState;
		pHaHost->nPriority = nPeerPriority;

		pHaHost->rAddr.sin_family = AF_INET;
		pHaHost->rAddr.sin_port = rAddr.sin_port;
		pHaHost->rAddr.sin_addr.s_addr = rAddr.sin_addr.s_addr;

		pHaHost->nHostType = nHostType;
		pHaHost->nConnectType = 2;	//主备连接
	}

	if (pHaHost->nOnTime == 0)
	{
		pHaHost->nOnTime = time(NULL);
		pHaHost->nOffTime = 0;

		/* tell statemgr STB host is online */
		if (nPeerRunningState == HA_STATE_STB)
		{
			HaEventNotify(HA_EVENT_HB_ON, pHaHost, sizeof(*pHaHost));
		}
	}
	
	/*process recv data*/
	if (pHaPktObj->nReqRespType == HA_PACKET_REQ)
	{
		//收到请求数据
		g_pHooks[pHaPktObj->nPaLoadType]->RequestCB(pHaPktObj, pHaHost);
	}
	else
	{
		//收到应答数据
		g_pHooks[pHaPktObj->nPaLoadType]->ResponseCB(pHaPktObj, pHaHost);
		
		//if (pHaPktObj->nPaLoadType == HA_PAYLOAD_ELECTION)
		if(g_pHooks[pHaPktObj->nPaLoadType]->LocalTimeoutCB)//是否需要对应答包做超时处理
		{ 
			//收到请求数据的应答数据包
			HaPendingObj rHaPendingObj;
			memset(&rHaPendingObj, 0, sizeof(rHaPendingObj));
			
			rHaPendingObj.pHaPktObj = pHaPktObj;

			HaPendingList* pHaPendingList = &g_rResponse[pHaPktObj->nPaLoadType];

			pthread_mutex_lock(&pHaPendingList->ht_mutex);
			HaPendingObj* pHaPendingObj = HashListTableLookup(pHaPendingList->pHashTable, &rHaPendingObj, sizeof(&rHaPendingObj));
			pthread_mutex_unlock(&pHaPendingList->ht_mutex);

			if (pHaPendingObj)
			{
				//删除与相应数据包相关的定时器、数据包缓冲区，调用相应应答包的处理函数
				event_del(pHaPendingObj->pTimerEvent);
				event_free(pHaPendingObj->pTimerEvent);

				pthread_mutex_lock(&pHaPendingList->ht_mutex);
				HashListTableRemove(pHaPendingList->pHashTable, pHaPendingObj, sizeof(pHaPendingObj));
				pthread_mutex_unlock(&pHaPendingList->ht_mutex);
				
				SCFree(pHaPendingObj->pHaPktObj);
				SCFree(pHaPendingObj);
			}
		}
	}
}

void* HaLoopthread(void* pArg)
{
	struct event_base* pHaEventBase = (struct event_base*)pArg;
	
	HA_LOG_DEBUG("basemgr running\n");
	int nReturn = event_base_loop(pHaEventBase, 0);
	HA_LOG_ERROR("loopthread return %d\n", nReturn);

	return NULL;
}

int ha_init_bcast_sock(const char* ifname)
{
	int nUdpSockFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (nUdpSockFd == -1)
	{
		HA_LOG_ERROR("Create udp socket failed.\n");
		return -1;
	}

	/*Set SO_REUSEADDR on the server/receive socket*/
	int j = 1;
	if (setsockopt(nUdpSockFd, SOL_SOCKET, SO_REUSEADDR, (const void*)&j, sizeof(j)) < 0)
	{
		HA_LOG_ERROR("Error setting socket option SO_REUSEADDR: %s\n", strerror(errno));
		return -1;
	}

	/*bind ha interface to nUdpSockFd*/
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	
	if (setsockopt(nUdpSockFd, SOL_SOCKET, SO_BINDTODEVICE, (char*)&ifr, sizeof(ifr)) == -1)
	{
		HA_LOG_ERROR("Error setting socket option"
			" SO_BINDTODEVICE(r) on %s: %s"
			, ifr.ifr_name, strerror(errno));
		return -1;
	}

	/*bind ip and port for server/receive socket, write socket don't need to bind */
	struct sockaddr_in bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind_addr.sin_port = htons(HaGetLocalPort());
	
	if (bind(nUdpSockFd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1)
	{
		HA_LOG_ERROR("Bind udp socket failed.\n");
		return -1;
	}

	/* Warn that we're going to broadcast, write socket need to set and receive socket need not to set*/
	int on = 1;
	if (setsockopt(nUdpSockFd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof(on)) == -1)
	{
		HA_LOG_ERROR("Error setting socket option SO_BROADCAST: %s\n", strerror(errno));
		return -1;
	}

	return nUdpSockFd;
}

int HaStartRead(HaBaseMgr* pHaBaseMgr)
{
    pHaBaseMgr->pRecvEvent = event_new(pHaBaseMgr->pHaEventBase, pHaBaseMgr->nUdpSockFd, EV_READ | EV_PERSIST, HaManagerOnDate, pHaBaseMgr);
	if (pHaBaseMgr->pRecvEvent != NULL)
	{
		event_add(pHaBaseMgr->pRecvEvent, NULL);
	}

	if (pHaBaseMgr->HbSendReqTimer != NULL)
	{
		struct timeval tvTimer;

		tvTimer.tv_sec = HaGetHeartbeatIntervalTime() / 1000;
		tvTimer.tv_usec = (HaGetHeartbeatIntervalTime() % 1000) * 1000;

		pHaBaseMgr->nTime = time(NULL);
		event_add(pHaBaseMgr->HbSendReqTimer, &tvTimer);
	}
	
	return 0;
}

uint32_t ha_get_broadcast_addr()
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));	
	strcpy(ifr.ifr_name, HaGetInterfaceName());
	
	int nSocketFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (nSocketFd == -1)
	{
		return 0;
	}
	
	if (ioctl(nSocketFd, SIOCGIFBRDADDR, &ifr) < 0)
	{
		close(nSocketFd);
		HA_LOG_ERROR("get broadcast addr failed!, %s\n", strerror(errno));
		return 0;
	}	
	close(nSocketFd);
	
	struct in_addr rAddr;
	rAddr.s_addr = ((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr.s_addr;

	return rAddr.s_addr;
}

int HaSendDataToStb(const char* pData, int nDataLen)
{
	int i = 2;
	int nWriteLen = 0;
	HaHost* pHaHost = NULL;	
	HaErrorCode nReturn = HA_ERROR_NOEXIST;

	for (; i < 4; i++)
	{
		pHaHost = &g_pHaBaseMgr->rHaHostArray[i];
		if (pHaHost->rAddr.sin_addr.s_addr == 0)
		{
			continue;
		}

		if ((pHaHost->nRunningState == HA_STATE_STB) && (pHaHost->nOnTime > 0) && (pHaHost->nConnectType == 2))
		{
			nWriteLen = send(pHaHost->nSyncFd, pData, nDataLen, 0);
			if (nWriteLen < 0)
			{
				HA_LOG_ERROR("send sync data error(%s)\n", strerror(errno));
				nReturn = HA_ERROR_ERROR;
			}
			else
			{
				nReturn = HA_SUCCESS;
			}				
		}
	}

	return nReturn;
}

void HaBackground(evutil_socket_t nSocketFd, short nFlag, void* pParam)
{
}

void ha_bcast_host_init()
{
	memset(&g_rBcastHost, 0, sizeof(g_rBcastHost));
	
	g_rBcastHost.rAddr.sin_family = AF_INET;
	g_rBcastHost.rAddr.sin_port = htons(HaGetLocalPort());
	g_rBcastHost.rAddr.sin_addr.s_addr = ha_get_broadcast_addr();

	g_rBcastHost.nOnTime = time(NULL);
}

int ha_base_mgr_init()
{	
	g_pHaBaseMgr = (HaBaseMgr*)SCMalloc(sizeof(HaBaseMgr));
	if (!g_pHaBaseMgr)
	{
		return HA_ERROR_NOMEM;
	}
		
	struct timeval tvTimeout = { 1, 1000 };

	memset(g_pHaBaseMgr, 0, sizeof(HaBaseMgr));
	evthread_use_pthreads();

	g_pHaBaseMgr->pHaEventBase = event_base_new();
	g_pHaBaseMgr->pBackgroudEvent = event_new(g_pHaBaseMgr->pHaEventBase, -1, EV_READ | EV_PERSIST, HaBackground, g_pHaBaseMgr);
	event_add(g_pHaBaseMgr->pBackgroudEvent, &tvTimeout);
	
	mutex_init(&g_pHaBaseMgr->seq_lock);
	mutex_init(&g_pHaBaseMgr->state_lock);

	g_pHaBaseMgr->nUdpSockFd = ha_init_bcast_sock(HaGetInterfaceName());

	pthread_create(&g_pHaBaseMgr->evthread, NULL, HaLoopthread, g_pHaBaseMgr->pHaEventBase);

	g_pHaBaseMgr->HbSendReqTimer = NULL;

	ha_bcast_host_init();

	HaStateNotifyRegister(HaStateCommonChangeCB);

	return HA_SUCCESS;
}

void ha_base_mgr_deinit()
{
	if (!g_pHaBaseMgr)
	{
		return;
	}
		
	pthread_cancel(g_pHaBaseMgr->evthread);
	mutex_destory(&g_pHaBaseMgr->seq_lock);
	mutex_destory(&g_pHaBaseMgr->state_lock);
	
	event_del(g_pHaBaseMgr->pBackgroudEvent);
	event_base_loopbreak(g_pHaBaseMgr->pHaEventBase);
	event_base_free(g_pHaBaseMgr->pHaEventBase);

	SCFree(g_pHaBaseMgr);
	g_pHaBaseMgr = NULL;
}

uint32_t HaGetPktSeqAndAdd()
{
	mutex_lock(&g_pHaBaseMgr->seq_lock);
	uint32_t nPacketSeq = g_pHaBaseMgr->nPacketSeq++;
	mutex_unlock(&g_pHaBaseMgr->seq_lock);
	
	return nPacketSeq;
}

void ReInitUdpSocket()
{
	if (g_pHaBaseMgr->pRecvEvent)
	{
		event_del(g_pHaBaseMgr->pRecvEvent);
	}
	if (g_pHaBaseMgr->nUdpSockFd > 0)
	{
		closesocket(g_pHaBaseMgr->nUdpSockFd);
	}

	g_pHaBaseMgr->nUdpSockFd = ha_init_bcast_sock(HaGetInterfaceName());

	event_assign(g_pHaBaseMgr->pRecvEvent, g_pHaBaseMgr->pHaEventBase, g_pHaBaseMgr->nUdpSockFd,
		EV_READ | EV_PERSIST, HaManagerOnDate, g_pHaBaseMgr);

	event_add(g_pHaBaseMgr->pRecvEvent, NULL);

	ha_bcast_host_init();
}

int HaStateCommonChangeCB(HAEvent nHaEvent, const char* pData, int nDataLen)
{
	HA_LOG_DEBUG("HaStateCommonChangeCB: %s\n", ha_event_to_str(nHaEvent));
	
	if (nHaEvent == HA_EVENT_CONF_RECOVER)
	{
		//设备主备机配置信息,重新进行初始化
		ReInitUdpSocket();
	}
	
	return 0;
}