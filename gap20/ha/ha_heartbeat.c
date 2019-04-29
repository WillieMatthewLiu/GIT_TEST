#include "app_common.h"
#include "bitops.h"
#include "cmd_common.h"

#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_heartbeat.h"
#include "ha_statemgr.h"

/***send heartbeat request packet*/
void SendHaHeartbeatPkt(HaHost* pHaHost)
{
	uint32_t nSequence = HaGetPktSeqAndAdd();

	HaHeartbeatReq rHeartbeatReq;
	memset(&rHeartbeatReq, 0, sizeof(rHeartbeatReq));

	rHeartbeatReq.dwIPAddr = HaGetLocalIP();
	rHeartbeatReq.dwMyMask = HaGetLocalMask();
	rHeartbeatReq.nMyState = HaGetLocalRunningState();
	rHeartbeatReq.nInitState = HaGetLocalState();
	rHeartbeatReq.nMyPriority = HaGetLocalPriority();	

	/*HA_LOG_DEBUG("send heartbeat request to %s, mystate: %s, seq: %d\n",
		inet_ntoa(pHaHost->rAddr.sin_addr),
		ha_state_to_str(rHeartbeatReq.nMyState), nSequence);*/
	
	/* send heartbeat pkt to other host */
	int nReturn = HaManagerSendData(HA_PACKET_REQ, HA_PAYLOAD_HEARTBEAT, nSequence,
		(uint8_t*)&rHeartbeatReq, sizeof(HaHeartbeatReq), pHaHost);
	if (nReturn < 0)
	{
		HA_LOG_ERROR("send heartbeat request failed, %s\n", inet_ntoa(pHaHost->rAddr.sin_addr));
	}
}

/***send heartbeat request packet to each host periodically*/
void HaHeartbeatSendReqTimer(evutil_socket_t nSocketFd, short nEvent, void* pArg)
{
	HaHost* pHaHost = NULL;
	HaBaseMgr* pHaBaseMgr = (HaBaseMgr*)pArg;

	//1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
	if (g_nBoardType == BOARDTYPE_IN)
	{
		pHaHost = &g_pHaBaseMgr->rHaHostArray[2];
	}
	else
	{
		pHaHost = &g_pHaBaseMgr->rHaHostArray[3];
	}

	if (pHaHost->rAddr.sin_addr.s_addr != 0)
	{
		if (pHaHost->rAddr.sin_port == 0)
		{
			pHaHost->rAddr.sin_port = htons(HaGetLocalPort());
		}
		SendHaHeartbeatPkt(pHaHost);
	}
	else
	{
		SendHaHeartbeatPkt(&g_rBcastHost);
	}
		
	int nTime = (time(NULL) - pHaBaseMgr->nTime) * 1000;
	if (nTime > HaGetHeartbeatMaxwaitTime())
	{
		//心跳检测超时		
		g_pHaBaseMgr->bConnected = FALSE;

		if(pHaHost != NULL)
		{
			if (pHaHost->nOnTime > 0)
			{
				pHaHost->nOnTime = 0;
				pHaHost->nOffTime = time(NULL);

				HaEventNotify(HA_EVENT_HB_LOSS, (char*)pHaHost, sizeof(HaHost));
				memset(pHaHost, 0, sizeof(HaHost));
			}		
			else
			{
				if (HaGetLocalRunningState() == HA_STATE_STB)
				{
					HaEventNotify(HA_EVENT_HB_LOSS, NULL, 0);
				}
			}
		}		
		else
		{
			if (g_rBcastHost.nOnTime > 0)
			{
				g_rBcastHost.nOnTime = 0;
				g_rBcastHost.nOffTime = time(NULL);

				HaEventNotify(HA_EVENT_HB_LOSS, NULL, 0);
			}
		}		
	}
}

/***callback hook when rcv heartbeat request packet*/
int HaHeartbeatReqCB(HaPktObject* pHaPktObj, HaHost* pHaHost)
{
	if (pHaHost == NULL)
	{
		HA_LOG_ERROR("heartbeat request occured, but can't find host in host list\n");
		return -1;
	}
	
	/*HA_LOG_DEBUG("recv heartbeat request from %s, mystate: %s, seq: %d\n",
						inet_ntoa(pHaHost->rAddr.sin_addr),
						ha_state_to_str(HaGetLocalRunningState()),
						pHaPktObj->nSequence);*/

	HaHeartbeatReq* pHeartbeatReq = (HaHeartbeatReq*)pHaPktObj->chData;
	
	pHaHost->nInitState = pHeartbeatReq->nInitState;
	pHaHost->nRunningState = pHeartbeatReq->nMyState;
	
	pHaHost->nPriority = pHeartbeatReq->nMyPriority;
	pHaHost->dwMask = pHeartbeatReq->dwMyMask;
	
	/* send heartbeat response */
	HaHeartbeatResp rHeartbeatResp;
	memset(&rHeartbeatResp, 0, sizeof(rHeartbeatResp));
	
	rHeartbeatResp.dwIPAddr = HaGetLocalIP();
	rHeartbeatResp.dwMyMask = HaGetLocalMask();

	rHeartbeatResp.nInitState = HaGetLocalState();
	rHeartbeatResp.nMyState = HaGetLocalRunningState();
	
	rHeartbeatResp.nMyPriority = HaGetLocalPriority();
		
	int nReturn = HaManagerSendData(HA_PACKET_RESP, HA_PAYLOAD_HEARTBEAT, pHaPktObj->nSequence,
		(uint8_t*)&rHeartbeatResp, sizeof(HaHeartbeatResp), pHaHost);
	if (nReturn < 0)
	{
		HA_LOG_ERROR("send heartbeat response failed\n");
	}

	return 0;
}

/***callback hook when rcv heartbeat response packet*/
int HaHeartbeatRespCB(HaPktObject* pHaRespPktObj, HaHost* pHaHost)
{		
	/*HA_LOG_DEBUG("recv heartbeat response from %s, mystate: %s\n", inet_ntoa(pHaHost->rAddr.sin_addr),
		ha_state_to_str(HaGetLocalRunningState()));*/
 
	HaHeartbeatResp* rHeartbeatResp = (HaHeartbeatResp*)pHaRespPktObj->chData;
	
	pHaHost->nRunningState = rHeartbeatResp->nMyState;
	pHaHost->nInitState = rHeartbeatResp->nInitState;
	pHaHost->nPriority = rHeartbeatResp->nMyPriority;
	pHaHost->dwMask = rHeartbeatResp->dwMyMask;

	HaState nRunningState = HaGetLocalRunningState();
	if (nRunningState == pHaHost->nRunningState)
	{
		//如果对端设备与本设备状态相同，以初始状态进行主机选举
		InoutSyncElectionRestart(HaGetLocalState());
	}

	return 0;
}

HaPacketHooks g_heartbeat_hooks = 
{
	HA_PAYLOAD_HEARTBEAT,
	"heartbeat hooks",
	HaHeartbeatReqCB,
	HaHeartbeatRespCB,
	NULL,
	NULL,
	NULL
};

int ha_heartbeat_init()
{
	if (ha_pkt_hooks_reg(&g_heartbeat_hooks) < 0)
	{
		return HA_ERROR_EXIST;
	}		

	g_pHaBaseMgr->HbSendReqTimer = event_new(g_pHaBaseMgr->pHaEventBase, -1, EV_PERSIST,
		HaHeartbeatSendReqTimer, g_pHaBaseMgr);
	
	return HA_SUCCESS;
}