#include "app_common.h"
#include "command.h"

#include "ha_inout.h"
#include "util-lock.h"
#include "bitops.h"

#define GAP_IN_SIDE		0
#define GAP_OUT_SIDE	1

static unsigned int	g_nCount = 0;				//定时器触发的次数
HaInoutMgr*			g_pHaInoutMgr = NULL;

int InoutStateChangeCallback(HAEvent nHaEvent, const char* pData, int nLength);
void InConnectTimer(evutil_socket_t nFd, short nEvent, void* pArg);

int InoutSyncElectionRestart(int nHaState)
{
	HA_LOG_DEBUG("InoutSyncElectionRestart start!\n");
	
	HaFaultNotifyMsg rNotifyMsg;
	
	rNotifyMsg.dwIPAddr = 0;
	rNotifyMsg.nFaultState = HA_FAULT_NONE;
	rNotifyMsg.nHaState = nHaState;
	
	HaSetElectionFaultNotifyMsg(&rNotifyMsg);

	sem_post(g_pHaBaseMgr->ha_mutex);

	return 0;
}

int InoutFaultElectionRestart(HaFaultNotifyMsg* pNotifyMsg)
{
	HaSetElectionFaultNotifyMsg(pNotifyMsg);
	sem_post(g_pHaBaseMgr->ha_mutex);

	return 0;
}

HaHost* InoutAddHost(uint32_t dwIPAddr, int nHostType)
{
	struct sockaddr_in rAddr;
	rAddr.sin_addr.s_addr = dwIPAddr;

	//根据对端主机类型获取主机数据保存地址
	HaHost* pHaHost = &g_pHaBaseMgr->rHaHostArray[nHostType - 1];
	if (pHaHost->rAddr.sin_addr.s_addr != rAddr.sin_addr.s_addr)
	{
		//主机不存在
		memset(pHaHost, 0, sizeof(HaHost));
		pHaHost->rAddr.sin_addr.s_addr = dwIPAddr;
	}
	
	return pHaHost;
}

void InoutAddHosts(HaInoutMgr* pInoutMgr)
{
	int nHostType = 0;
	if (pInoutMgr->nSide == GAP_IN_SIDE)
	{
		nHostType = 2;	//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
	}
	else
	{
		nHostType = 1;
	}
	
	HaHost* pHaHost = InoutAddHost(pInoutMgr->pRecvMsg->u.rSyncMsg.dwIPAddr, nHostType);
	
	pHaHost->nInitState = pInoutMgr->pRecvMsg->u.rSyncMsg.nInitState;
	pHaHost->nRunningState = pInoutMgr->pRecvMsg->u.rSyncMsg.nRunningState;
	pHaHost->nPriority = pInoutMgr->pRecvMsg->u.rSyncMsg.nPriority;

	pHaHost->dwMask = pInoutMgr->pRecvMsg->u.rSyncMsg.dwMask;

	if (pHaHost->nOnTime == 0)
	{
		pHaHost->nOnTime = time(NULL);
	}
	if (pHaHost->nOffTime > 0)
	{
		pHaHost->nOffTime = 0;
	}

	pHaHost->nHostType = nHostType;
	pHaHost->nConnectType = 1;	//0： 未知； 1：内外端连接  2：主备连接

	HaState nPeerRunningState = pHaHost->nRunningState;
	
	HaInoutHostInfo* pInoutHostInfo = (HaInoutHostInfo*)pInoutMgr->pRecvMsg->u.rSyncMsg.chData;
	while (pInoutMgr->pRecvMsg->u.rSyncMsg.nHostCount)
	{
		pHaHost = InoutAddHost(pInoutHostInfo->dwIPAddr, pInoutHostInfo->nHostType);

		pHaHost->nInitState = pInoutHostInfo->nInitState;
		pHaHost->nRunningState = pInoutHostInfo->nRunningState;
		pHaHost->nPriority = pInoutHostInfo->nPriority;

		pHaHost->dwMask = pInoutHostInfo->dwMask;		
		
		pHaHost->nOnTime = pInoutHostInfo->nOnTime;
		pHaHost->nOffTime = pInoutHostInfo->nOffTime;

		pHaHost->nHostType = pInoutHostInfo->nHostType;
		pHaHost->nConnectType = pInoutHostInfo->nConnectType;

		pInoutMgr->pRecvMsg->u.rSyncMsg.nHostCount--;

		pInoutHostInfo++;
	}

	HaState nHaState = HaGetLocalRunningState();
	if (nPeerRunningState != nHaState)
	{
		//内外端机状态不一致				
		if (g_pHaInoutMgr->nSide == GAP_IN_SIDE)//内端机
		{
			if (g_pHaInoutMgr->bSwitchState)
			{
				//在通知对端进行主备状态切换时，暂停一次状态同步
				__sync_lock_test_and_set(&g_pHaInoutMgr->bSwitchState, FALSE);
				return;
			}

			if (!g_pHaBaseMgr->bConnected)
			{
				//如果另一台设备没有在线
				nHaState = HA_STATE_ACT;
			}
			else
			{
				nHaState = HA_STATE_STB;
			}

			//内端机发起主机选举
			InoutSyncElectionRestart(nHaState);
		}
	}
}

void InoutReSend(HaInoutMgr* pInoutMgr)
{
	if (pInoutMgr->nSocketFd != -1)
	{
		int nWriteSize = send(pInoutMgr->nSocketFd, pInoutMgr->chDataBuffer, sizeof(HaInoutPacket), 0);
		if (nWriteSize < 0)
		{
			HA_LOG_ERROR("inout send error(%s)\n", strerror(errno));
		}

		g_pHaInoutMgr->bHaveReSendData = FALSE;
	}
}

void CloseInout(HaInoutMgr* pInoutMgr)
{
	if (pInoutMgr->nSocketFd == -1)
	{
		return;
	}

	if (pInoutMgr->pReadEvent != NULL)
	{
		event_del(pInoutMgr->pReadEvent);
		event_free(pInoutMgr->pReadEvent);
		pInoutMgr->pReadEvent = NULL;
	}

	pInoutMgr->bConnected = FALSE;

	closesocket(pInoutMgr->nSocketFd);
	pInoutMgr->nSocketFd = -1;

	HaHost* pHaHost = NULL;

	if (GAP_IN_SIDE == pInoutMgr->nSide)
	{
		//InnerConnectOuter(pInoutMgr);
		//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
		pHaHost = &g_pHaBaseMgr->rHaHostArray[1];
	}
	else
	{
		pHaHost = &g_pHaBaseMgr->rHaHostArray[0];
	}

	pHaHost->nOnTime = 0;
	pHaHost->nOffTime = time(NULL);
	
	InoutSyncElectionRestart(HA_STATE_STB);
	
	memset(pHaHost, 0, sizeof(HaHost));
}

int InoutSend(HaInoutPacket* pData, int nLength)
{
	HaErrorCode nReturn = HA_SUCCESS;
	
	if (g_pHaInoutMgr->nSocketFd <= 0)
	{		
		memcpy(g_pHaInoutMgr->chDataBuffer, pData, nLength);
		g_pHaInoutMgr->bHaveReSendData = TRUE;
		return HA_SUCCESS;
	}

	int nWriteSize = send(g_pHaInoutMgr->nSocketFd, pData, nLength, 0);
	if (nWriteSize < 0)
	{
		HA_LOG_ERROR("inout send error(%s)\n", strerror(errno));
		CloseInout(g_pHaInoutMgr);
		
		return -HA_ERROR_ERROR;
	}	

	return nReturn;
}

void InoutProcessConfigMsg(HaConfMsg* pConfMsg)
{
	char* pDate = pConfMsg->chData;

	switch (pConfMsg->nMsgType)
	{
	case HA_CONF_MSG_STOP_TIMER:
		HA_LOG_DEBUG("stop timer ...\n");
		HaEventNotify(HA_EVENT_CONF_STOP_TIMER, NULL, 0);
		break;

	case HA_CONF_MSG_CONFIGURATION_CMDS:
		SaveLocalConfigurationCmds(pDate, pConfMsg->nLength);
		break;
 
	case HA_CONF_MSG_CLOSE_SOCKET:
		HA_LOG_DEBUG("close sync socket ...\n");
		HaEventNotify(HA_EVENT_CONF_CLOSE_SOCKET, NULL, 0);
		break;
		
	case HA_CONF_MSG_RECOVER:
		HA_LOG_DEBUG("recover ...\n");
		ApplyLocalConfigurationCmds();
		usleep(100 * 1000);
		HaEventNotify(HA_EVENT_CONF_RECOVER, NULL, 0);
		break;
		
	case HA_CONF_MSG_GO_OOS:
		HA_STATE_GO_OOS;
		break;
		
	case HA_CONF_MSG_REELECTION:
		sem_post(g_pHaBaseMgr->ha_mutex);
		break;
		
	default:
		HA_LOG_DEBUG("Unrecognized msg type %d ...\n", pConfMsg->nMsgType);
		break;
	}
}

static void InoutRecvData(evutil_socket_t nSocketFd, short nEvent, void* pArg)
{
	HaInoutMgr* pInoutMgr = (HaInoutMgr*)pArg;

	int nReadSize = recv(pInoutMgr->nSocketFd, pInoutMgr->chDataBuffer, INOUT_MAX_MESSAGE_LEN, 0);	
	if (nReadSize < 0)
	{
		HA_LOG_ERROR("InoutRecvData error, %s\n", strerror(errno));
		CloseInout(pInoutMgr);
		return;
	}
	else if (nReadSize == 0)
	{
		//网络断开
		HA_LOG_ERROR("InoutRecvData peer disconnect\n");
		CloseInout(pInoutMgr);
		return;
	}

	//更新最近一次接收到数据的时间
	pInoutMgr->nTime = time(NULL);
	
	pInoutMgr->pRecvMsg = (HaInoutPacket*)pInoutMgr->chDataBuffer;

	//HA_LOG_DEBUG("Inout message Type = %d, nMsgID = %d\n", pInoutMgr->pRecvMsg->nType, g_pHaInoutMgr->pRecvMsg->nMsgID);

	if (pInoutMgr->pRecvMsg->nType == HA_INOUT_PACKET_RESP)
	{
		//内端机收到应答数据包
		if (g_pHaInoutMgr->pRecvMsg)
		{
			/* process recv msg */
			if (g_pHaInoutMgr->pRecvMsg->nMsgID == HA_INOUT_STATE_SYNC)
			{
				//内外端状态同步
				memset(&g_pHaBaseMgr->rHaHostArray[3], 0, sizeof(HaHost));

				InoutAddHosts(g_pHaInoutMgr);
			}
		}
	}
	else  if (pInoutMgr->pRecvMsg->nType == HA_INOUT_PACKET_REQ)
	{
		//外端机收到请求数据包
		if (pInoutMgr->pRecvMsg->nMsgID == HA_INOUT_STATE_SYNC)
		{
			//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
			memset(&g_pHaBaseMgr->rHaHostArray[2], 0, sizeof(HaHost));

			//内外端状态同步
			HaInoutPacket rInoutPacket;
			memset(&rInoutPacket, 0, sizeof(rInoutPacket));
			
			rInoutPacket.nType = HA_INOUT_PACKET_RESP;
			rInoutPacket.nMsgID = HA_INOUT_STATE_SYNC;
			
			rInoutPacket.u.rSyncMsg.nInitState = HaGetLocalState();
			rInoutPacket.u.rSyncMsg.nRunningState = HaGetLocalRunningState();			
			rInoutPacket.u.rSyncMsg.nPriority = HaGetLocalPriority();

			rInoutPacket.u.rSyncMsg.dwIPAddr = HaGetLocalIP();
			rInoutPacket.u.rSyncMsg.dwMask = HaGetLocalMask();
			rInoutPacket.u.rSyncMsg.nHostCount = 0;

			int i = 1;
			HaHost* pHaHost = NULL;
			HaInoutHostInfo rInoutHostInfo;
			memset(&rInoutHostInfo, 0, sizeof(rInoutHostInfo));
		
			for (; i < 4; i++)
			{
				pHaHost = &g_pHaBaseMgr->rHaHostArray[i];
				if (pHaHost->rAddr.sin_addr.s_addr == 0)
				{
					continue;
				}

				if (pHaHost->nHostType != 1)//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
				{		
					//不是本设备的内端机
					rInoutHostInfo.nInitState = pHaHost->nInitState;
					rInoutHostInfo.nRunningState = pHaHost->nRunningState;
					rInoutHostInfo.nPriority = pHaHost->nPriority;

					rInoutHostInfo.dwIPAddr = pHaHost->rAddr.sin_addr.s_addr;
					rInoutHostInfo.dwMask = pHaHost->dwMask;
										
					rInoutHostInfo.nOnTime = pHaHost->nOnTime;
					rInoutHostInfo.nOffTime = pHaHost->nOffTime;

					rInoutHostInfo.nHostType = pHaHost->nHostType;
					
					//3: 对端内端机 4: 对端外端机
					//rInoutHostInfo.nHostType = 4;
					
					memcpy(rInoutPacket.u.rSyncMsg.chData + rInoutPacket.u.rSyncMsg.nHostCount * sizeof(HaInoutHostInfo), 
						&rInoutHostInfo, sizeof(HaInoutHostInfo));
					rInoutPacket.u.rSyncMsg.nHostCount++;
				}
			}

			InoutSend(&rInoutPacket, sizeof(HaInoutPacket));

			InoutAddHosts(pInoutMgr);
		}

	}
	else if (pInoutMgr->pRecvMsg->nType == HA_INOUT_PACKET_NOTIFY)//内外端通知
	{
		/*******************************************************************************************************************
			if msgid is STATE_SYNC:

			if msgid is HB_LOSS:
			if local host has peer host and its ha state is not same with its inner or outer, force to reelect.
			if local host has not peer host and its ha state is not same with its inner or outer, force to go_act or go_stb.
		*******************************************************************************************************************/
		if (pInoutMgr->pRecvMsg->nMsgID == HA_INOUT_STATE_SYNC)
		{
			HaState nHaState = pInoutMgr->pRecvMsg->u.rNotifyMsg.nHaState;
			HaState nRunningState = HaGetLocalRunningState();

			HA_LOG_DEBUG("NOTIFY: local running_state: %s, peer_running_state: %s\n", 
				ha_state_to_str(nRunningState),	ha_state_to_str(nHaState));

			if (nHaState != nRunningState)
			{				
				if (GAP_OUT_SIDE == pInoutMgr->nSide)
				{
					//只对外端机更新状态
					InoutSyncElectionRestart(pInoutMgr->pRecvMsg->u.rNotifyMsg.nHaState);
				}				
			}
		}
		else if (pInoutMgr->pRecvMsg->nMsgID == HA_INOUT_FAULT_NOTIFY)
		{
			HaState nHaState = pInoutMgr->pRecvMsg->u.rNotifyMsg.nHaState;
			HaState nRunningState = HaGetLocalRunningState();

			HA_LOG_DEBUG("Recv fault, fault_state: %d, local running_state: %s, peer_running_state: %s\n",
				pInoutMgr->pRecvMsg->u.rNotifyMsg.nFaultState,
				ha_state_to_str(nRunningState),
				ha_state_to_str(nHaState));

			if (nHaState != nRunningState)
			{
				InoutFaultElectionRestart(&pInoutMgr->pRecvMsg->u.rNotifyMsg);
			}
		}
		else
		{
			InoutProcessConfigMsg(&pInoutMgr->pRecvMsg->u.rConfigMsg);
		}
	}
}

BOOL InGetParterState(HaInoutMgr* pInoutMgr)
{
	if (pInoutMgr->nSocketFd < 0)
	{
		return FALSE;
	}

	HaInoutPacket rInoutPacket;
	memset(&rInoutPacket, 0, sizeof(rInoutPacket));

	HaState nRunningState = HaGetLocalRunningState();

	rInoutPacket.nType = HA_INOUT_PACKET_REQ;
	rInoutPacket.nMsgID = HA_INOUT_STATE_SYNC;

	rInoutPacket.u.rSyncMsg.nInitState = HaGetLocalState();
	rInoutPacket.u.rSyncMsg.nRunningState = nRunningState;

	rInoutPacket.u.rSyncMsg.nPriority = HaGetLocalPriority();

	rInoutPacket.u.rSyncMsg.dwIPAddr = HaGetLocalIP();
	rInoutPacket.u.rSyncMsg.dwMask = HaGetLocalMask();
	rInoutPacket.u.rSyncMsg.nHostCount = 0;

	HaHost* pHaHost = NULL;
	HaInoutHostInfo rInoutHostInfo;
	memset(&rInoutHostInfo, 0, sizeof(rInoutHostInfo));

	int i = 0;
	for (; i < 4; i++)
	{
		pHaHost = &g_pHaBaseMgr->rHaHostArray[i];
		if (pHaHost->rAddr.sin_addr.s_addr == 0)
		{
			continue;
		}

		if (pHaHost->nHostType != 2)//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
		{
			//不是本设备的外端机
			rInoutHostInfo.nInitState = pHaHost->nInitState;
			rInoutHostInfo.nRunningState = pHaHost->nRunningState;
			rInoutHostInfo.nPriority = pHaHost->nPriority;

			rInoutHostInfo.dwIPAddr = pHaHost->rAddr.sin_addr.s_addr;
			rInoutHostInfo.dwMask = pHaHost->dwMask;
			
			rInoutHostInfo.nOnTime = pHaHost->nOnTime;
			rInoutHostInfo.nOffTime = pHaHost->nOffTime;
			
			rInoutHostInfo.nHostType = pHaHost->nHostType;
			rInoutHostInfo.nConnectType = pHaHost->nConnectType;			

			//3: 对端内端机 4: 对端外端机
			//rInoutHostInfo.nHostType = 3;

			memcpy(rInoutPacket.u.rSyncMsg.chData + rInoutPacket.u.rSyncMsg.nHostCount * sizeof(HaInoutHostInfo), 
				&rInoutHostInfo, sizeof(HaInoutHostInfo));
			rInoutPacket.u.rSyncMsg.nHostCount++;
		}
	}

	int nReturn = InoutSend(&rInoutPacket, sizeof(HaInoutPacket));
	if (nReturn < 0)
	{
		HA_LOG_DEBUG("InGetParterState failed\n");
		CloseInout(pInoutMgr);

		return FALSE;
	}

	return TRUE;
}

BOOL InnerConnectOuter(HaInoutMgr* pInoutMgr)
{
	struct sockaddr_in rAddr;

	rAddr.sin_family = AF_INET;
	rAddr.sin_addr.s_addr = pInoutMgr->dwPeerIP;
	rAddr.sin_port = htons(pInoutMgr->nPeerPort);

	int nSocketFd = socket(AF_INET, SOCK_STREAM, 0);
	if (nSocketFd == -1)
	{
		return FALSE;
	}

	if (connect(nSocketFd, &rAddr, sizeof(rAddr)) < 0)
	{
		HA_LOG_DEBUG("connect %s failed, %s\n", inet_ntoa(rAddr.sin_addr), strerror(errno));		
		return FALSE;
	}

	if (pInoutMgr->bHaveReSendData)
	{
		//还有未发送成功的数据，重新发送一次
		InoutReSend(pInoutMgr);
	}

	pInoutMgr->nSocketFd = nSocketFd;
	pInoutMgr->bConnected = TRUE;
	pInoutMgr->nTime = time(NULL);
			
	int nHaState = HaGetLocalRunningState();
	if (nHaState == HA_STATE_ACT)
	{
		/* sync ha state again */
		HaInoutPacket rInoutPacket;
		memset(&rInoutPacket, 0, sizeof(rInoutPacket));

		rInoutPacket.nType = HA_INOUT_PACKET_NOTIFY;
		rInoutPacket.nMsgID = HA_INOUT_STATE_SYNC;

		rInoutPacket.u.rNotifyMsg.nFaultState = HA_FAULT_NONE;
		rInoutPacket.u.rNotifyMsg.nHaState = HA_STATE_ACT;
		rInoutPacket.u.rNotifyMsg.dwIPAddr = 0;

		InoutSend(&rInoutPacket, sizeof(rInoutPacket));
	}
	else
	{
		if (!g_pHaBaseMgr->bConnected)
		{
			//如果另一台设备没有在线
			nHaState = HA_STATE_ACT;
		}
		else
		{
			nHaState = HA_STATE_STB;
		}

		InoutSyncElectionRestart(nHaState);
	}
	
	/* add this to event base for read */
	if (pInoutMgr->pReadEvent != NULL)
	{
		event_del(pInoutMgr->pReadEvent);
		event_free(pInoutMgr->pReadEvent);
		pInoutMgr->pReadEvent = NULL;
	}

	pInoutMgr->pReadEvent = event_new(pInoutMgr->pInoutEventBase, pInoutMgr->nSocketFd, EV_READ|EV_PERSIST, InoutRecvData, pInoutMgr);
	if (pInoutMgr->pReadEvent != NULL)
	{
		event_add(pInoutMgr->pReadEvent, NULL);
	}
	
	return TRUE;
}

void OutOnAccept(evutil_socket_t nListenFd, short nEvent, void* pArg)
{
	HaInoutMgr* pInoutMgr = (HaInoutMgr*)pArg;
	if (pInoutMgr == NULL)
	{
		return;
	}
	
	if (pInoutMgr->nSocketFd > 0)
	{
		//已经有内端机连接，断开以前的连接
		closesocket(pInoutMgr->nSocketFd);
		pInoutMgr->nSocketFd = -1;
				
		HaHost* pHaHost = &g_pHaBaseMgr->rHaHostArray[0];
		if (pHaHost != NULL)
		{
			//将内端机状态置为断线
			pHaHost->nOnTime = 0;
			pHaHost->nOffTime = time(NULL);
		}
	}
	
	struct sockaddr_in rAddr;
	socklen_t nAddrLen = sizeof(rAddr);

	int nSocketFd = accept(nListenFd, (struct sockaddr*)&rAddr, &nAddrLen);
	if (nSocketFd < 0)
	{
		return;
	}
		
	pInoutMgr->nSocketFd = nSocketFd;
	pInoutMgr->dwPeerIP = rAddr.sin_addr.s_addr;
	pInoutMgr->nPeerPort = ntohs(((struct sockaddr_in*)&rAddr)->sin_port);
	pInoutMgr->bConnected = TRUE;
	pInoutMgr->nTime = time(NULL);

	int nHaState = HaGetLocalRunningState();
	if (nHaState != HA_STATE_ACT)
	{
		if (!g_pHaBaseMgr->bConnected)
		{
			//如果另一台设备没有在线
			nHaState = HA_STATE_ACT;
		}
		else
		{
			nHaState = HA_STATE_STB;
		}
		InoutSyncElectionRestart(nHaState);
	}

	if (pInoutMgr->pReadEvent != NULL)
	{
		event_del(pInoutMgr->pReadEvent);
		event_free(pInoutMgr->pReadEvent);
		pInoutMgr->pReadEvent = NULL;
	}
	pInoutMgr->pReadEvent = event_new(pInoutMgr->pInoutEventBase, nSocketFd, EV_READ|EV_PERSIST, InoutRecvData, pInoutMgr);
	
	if (pInoutMgr->pReadEvent != NULL)
	{
		event_add(pInoutMgr->pReadEvent, NULL);
	}
}

void InoutBackground(evutil_socket_t nSocketFd, short nFlag, void* pParam)
{
	g_nCount++;
	if (g_pHaBaseMgr->bStopTimer)
	{
		g_pHaInoutMgr->nTime = time(NULL);
	}

	if (g_pHaInoutMgr->nSide == GAP_IN_SIDE)//内端机
	{
		//每秒检查一次与外端机的连接是否正常，不正常重新连接
		if(!g_pHaInoutMgr->bConnected)
		{
			InnerConnectOuter(g_pHaInoutMgr);
		}
		else
		{
			if ((g_nCount % 3) == 0)
			{				
				//连接正常，每3秒发一次包与外端机进行主机状态同步
				if (g_pHaInoutMgr->bSwitchState)
				{
					//在通知对端进行主备状态切换时，暂停一次状态同步
					__sync_lock_test_and_set(&g_pHaInoutMgr->bSwitchState, FALSE);
					g_pHaInoutMgr->nTime = time(NULL);
				}
				else
				{
					InGetParterState(g_pHaInoutMgr);
				}				
				
				if ((time(NULL) - g_pHaInoutMgr->nTime) > 10)
				{
					HA_LOG_DEBUG("********************inner recv data time out over ten second****************************");

					//如果10秒钟内没有收到对端发送的数据，断开连接
					CloseInout(g_pHaInoutMgr);					
				}
			}
		}
	}
	else
	{
		if (g_pHaInoutMgr->bConnected)
		{
			if ((time(NULL) - g_pHaInoutMgr->nTime) > 10)
			{
				//如果10秒钟内没有收到对端发送的数据，断开连接
				HA_LOG_DEBUG("********************outer recv data time out over ten second****************************");
				CloseInout(g_pHaInoutMgr);
			}
		}
	}
	
	if (!CheckBusinessInif())
	{
		//业务口的网线没能有接上
		int nHaState = HaGetLocalRunningState();
		if (nHaState == HA_STATE_ACT)
		{
			//当前设备为主机，将状态设置为备机
			HaFaultNotifyMsg rNotifyMsg;
			
			rNotifyMsg.dwIPAddr = HaGetLocalIP();
			rNotifyMsg.nFaultState = HA_FAULT_NONE;
			rNotifyMsg.nHaState = HA_STATE_STB;
			
			HaSetElectionFaultNotifyMsg(&rNotifyMsg);

			sem_post(g_pHaBaseMgr->ha_mutex);
		}
	}
}

void* InoutLoopthread(void* pArg)
{
	struct event_base* pInoutEventBase = (struct event_base*)pArg;
	
	HA_LOG_DEBUG("InoutMgr running\n");
	int nReturn = event_base_loop(pInoutEventBase, 0);
	HA_LOG_ERROR("InoutLoopthread return %d\n", nReturn);
	
	return NULL;
}

void inout_base_init(HaInoutMgr* pInoutMgr)
{	
	struct timeval tvTimer = { LIBEVENT_DEFAULT_TIMER, 0 };
	
	pInoutMgr->pInoutEventBase = event_base_new();
	pInoutMgr->pBackgroudEvent = event_new(pInoutMgr->pInoutEventBase, -1, EV_PERSIST, InoutBackground, pInoutMgr);
	
	event_add(pInoutMgr->pBackgroudEvent, &tvTimer);

	pthread_t nThreadID = 0;
	pthread_create(&nThreadID, NULL, InoutLoopthread, pInoutMgr->pInoutEventBase);
}

int partner_init_in(const char* pInSideIP, const char* pOutSideIP, uint16_t nPort)
{
	HA_LOG_DEBUG("in_side_ip: %s, out_side_ip: %s, port: %d\n", pInSideIP, pOutSideIP, nPort);

	g_pHaInoutMgr = (HaInoutMgr*)SCMalloc(sizeof(HaInoutMgr));
	memset(g_pHaInoutMgr, 0, sizeof(HaInoutMgr));

	g_pHaInoutMgr->nSocketFd = -1;
	g_pHaInoutMgr->nSide = GAP_IN_SIDE;

	g_pHaInoutMgr->dwLocalIP = inet_addr(pInSideIP);
	g_pHaInoutMgr->dwPeerIP = inet_addr(pOutSideIP);
	g_pHaInoutMgr->nPeerPort = nPort;

	inout_base_init(g_pHaInoutMgr);

	InnerConnectOuter(g_pHaInoutMgr);
	HaStateNotifyRegister(InoutStateChangeCallback);

	return HA_SUCCESS;
}

/**	init for out side board, will list in side board connect it*/
int partner_init_out(const char* pOutSideIP, uint16_t nPort)
{	
	HA_LOG_DEBUG("out_side_ip: %s\n", pOutSideIP);

	int nSocketFd = socket(AF_INET, SOCK_STREAM, 0);
	if (nSocketFd < 0)
	{
		HA_LOG_ERROR("create socket fail.\n");
		return -HA_ERROR_ERROR;
	}

	int nOn = 1;
	if (setsockopt(nSocketFd, SOL_SOCKET, SO_REUSEADDR, (const void*)&nOn, sizeof(nOn)) < 0)
	{
		HA_LOG_ERROR("Error setting socket option SO_REUSEADDR: %s\n", strerror(errno));
		return -HA_ERROR_ERROR;
	}

	setsockopt(nSocketFd, SOL_SOCKET, SO_REUSEPORT, (const void*)&nOn, sizeof(nOn));

	struct sockaddr_in rAddr;
	
	rAddr.sin_family = AF_INET;
	rAddr.sin_addr.s_addr = inet_addr(pOutSideIP);
	rAddr.sin_port = htons(nPort);

	if (bind(nSocketFd, &rAddr, sizeof(rAddr)) < 0)
	{
		HA_LOG_ERROR("bind fail(%s).", strerror(errno));
		close(nSocketFd);
		return -HA_ERROR_ERROR;
	}

	listen(nSocketFd, 5);

	g_pHaInoutMgr = (HaInoutMgr*)SCMalloc(sizeof(HaInoutMgr));
	memset(g_pHaInoutMgr, 0, sizeof(HaInoutMgr));

	g_pHaInoutMgr->nSocketFd = -1;

	g_pHaInoutMgr->dwLocalIP = rAddr.sin_addr.s_addr;
	g_pHaInoutMgr->nLocalPort = nPort;

	g_pHaInoutMgr->nAcceptFd = nSocketFd;
	g_pHaInoutMgr->nSide = GAP_OUT_SIDE;

	inout_base_init(g_pHaInoutMgr);

	/* add this to event base for accept */
	g_pHaInoutMgr->pAcceptEvent = event_new(g_pHaInoutMgr->pInoutEventBase, nSocketFd, EV_READ | EV_PERSIST, OutOnAccept, g_pHaInoutMgr);
	event_add(g_pHaInoutMgr->pAcceptEvent, NULL);

	HaStateNotifyRegister(InoutStateChangeCallback);
	
	return HA_SUCCESS;
}

int InoutStateChangeCallback(HAEvent nHaEvent, const char* pData, int nLength)
{
	HA_LOG_DEBUG("InoutStateChangeCallback: %s\n", ha_event_to_str(nHaEvent));
	
	int nHaState = 0;
	HaInoutPacket rInoutPacket;
	memset(&rInoutPacket, 0, sizeof(rInoutPacket));
	
	rInoutPacket.nType = HA_INOUT_PACKET_NOTIFY;
	if (nHaEvent == HA_EVENT_GO_ACT)
	{
		/* send ACT to other side */
		nHaState = HA_STATE_ACT;
	}
	else if (nHaEvent == HA_EVENT_GO_STB)
	{
		/* send STB to other side */
		nHaState = HA_STATE_STB;
	}
	else if (nHaEvent == HA_EVENT_CONF_STOP_TIMER)
	{
		/* stop inout_timer of inner*/	
		g_pHaBaseMgr->bStopTimer = TRUE;
		return HA_SUCCESS;
	}
	else if (nHaEvent == HA_EVENT_CONF_RECOVER)
	{
		return HA_SUCCESS;
	}
	else
	{
		return HA_SUCCESS;
	}
			
	HA_LOG_DEBUG("InoutStateChangeCallback %s\n", ha_state_to_str(nHaState));

	//当HA主备状态切换时，通知对端进行切换
	HaFaultNotifyMsg* pNotifyMsg = HaGetInoutFaultNotifyMsg();
	if (pNotifyMsg->nFaultState == HA_FAULT_NONE)
	{
		rInoutPacket.nMsgID = HA_INOUT_STATE_SYNC;

		rInoutPacket.u.rNotifyMsg.nFaultState = HA_FAULT_NONE;
		rInoutPacket.u.rNotifyMsg.nHaState = nHaState;
		rInoutPacket.u.rNotifyMsg.dwIPAddr = 0;
	}
	else
	{
		rInoutPacket.nMsgID = HA_INOUT_FAULT_NOTIFY;

		rInoutPacket.u.rNotifyMsg.nFaultState = pNotifyMsg->nFaultState;
		rInoutPacket.u.rNotifyMsg.nHaState = HA_STATE_ACT;// pNotifyMsg->nHaState;
		rInoutPacket.u.rNotifyMsg.dwIPAddr = pNotifyMsg->dwIPAddr;
	}

	//在通知对端进行主备状态切换时，暂停一次状态同步
	__sync_lock_test_and_set(&g_pHaInoutMgr->bSwitchState, TRUE);

	InoutSend(&rInoutPacket, sizeof(rInoutPacket));
	if (pNotifyMsg->nFaultState)
	{
		memset(pNotifyMsg, 0, sizeof(*pNotifyMsg));
	}
		
	return HA_SUCCESS;
}