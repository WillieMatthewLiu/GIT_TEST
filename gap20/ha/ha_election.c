#include "app_common.h"
#include "bitops.h"
//#include "ha_serialize.h"
#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_election.h"
#include "ha_statemgr.h"
#include "ha_heartbeat.h"

int HaElectionResponse(HaState nHaState, uint8_t nPriority, uint16_t nFlags, uint32_t nSequence, HaHost* pHaHost)
{
	HaElectionResp rElectionResp;
	memset(&rElectionResp, 0, sizeof(rElectionResp));

	rElectionResp.nMyState = nHaState;
	rElectionResp.nMyPriority = nPriority;
	rElectionResp.nFlags = nFlags;

	int nReturn = HaManagerSendData(HA_PACKET_RESP, HA_PAYLOAD_ELECTION, nSequence, (uint8_t*)&rElectionResp,
		sizeof(HaElectionResp), pHaHost);
	if (nReturn == -1)
	{
		HA_LOG_ERROR("send election response failed\n");
		return -1;
	}

	return 0;
}

/************************************************************************************
 ***send broadcast election packet.
 ***nHaState	初始状态
 ***nPriority	优先级
 ***nFlags		要设置的状态类型 0、HA_FLAG_FORCE_ACT或HA_FLAG_FORCE_STB
 ***pHaHost		消息接收方
 ***pNotifyMsg	通知消息内容 pNotifyMsg->nHaState为对方将要设置的HA状态
 ************************************************************************************/
int HaElectionRequest(HaState nHaState, uint8_t nPriority, uint16_t nFlags,
	HaHost* pHaHost, HaFaultNotifyMsg* pNotifyMsg)
{
	HaElectionReq rElectionReq;
	memset(&rElectionReq, 0, sizeof(rElectionReq));

	rElectionReq.nMyState = nHaState;
	rElectionReq.nMyPriority = nPriority;
	rElectionReq.nFlags = nFlags;
	
	rElectionReq.rNotifyMsg.nFaultState = pNotifyMsg->nFaultState;
	rElectionReq.rNotifyMsg.nHaState = pNotifyMsg->nHaState;
	rElectionReq.rNotifyMsg.dwIPAddr = pNotifyMsg->dwIPAddr;

	int nReturn = HaManagerSendData(HA_PACKET_REQ, HA_PAYLOAD_ELECTION, HaGetPktSeqAndAdd(),
		(uint8_t*)&rElectionReq, sizeof(HaElectionReq), pHaHost);
	if (nReturn == -1)
	{
		HA_LOG_ERROR("send election request failed\n");
		return -1;
	}

	return 0;
}

/***callback hook when rcv election request packet*/
int HaElectionReqCB(HaPktObject* pHaPktObj, HaHost* pHaHost)
{	
	HaElectionReq* pElectionReq = (HaElectionReq*)(pHaPktObj->chData);

	HaState nLocalState = HaGetLocalState();
	uint8_t nLocalPriority = HaGetLocalPriority();
	HaState nRunningState = HaGetLocalRunningState();

	HA_LOG_DEBUG("req_state: %s, req_priority: %d, req_flags: %d\n", ha_state_to_str(pElectionReq->nMyState),
		pElectionReq->nMyPriority, pElectionReq->nFlags);
	HA_LOG_DEBUG("local_state: %s, local_priority: %d, running_state: %s\n", ha_state_to_str(nLocalState),
		nLocalPriority, ha_state_to_str(nRunningState));

	/****************************************************************************************
	 if local host run as ACT:
		if peer request is FORCE_ACT, local host fallback to OOS.
		if peer request is FORCE_STB, local host response MY is ACT.
		if peer request is ACT/STB, local response MY is ACT, peer run as STB.

	   if local host run as STB:
	   if have a ACT host in system, just response MY is STB.
	   if peer request is FORCE_STB, local host response MY is ACT and reelect.

	   if local host run as OOS:
		compare state, priority, ip to judge who will run as ACT.

	   otherwise, drop this packet.
	*****************************************************************************************/
	
	uint8_t nLocalFlag = 0;	
	if (nRunningState == HA_STATE_ACT)
	{
		//本设备为主机
		if (pElectionReq->nFlags & HA_FLAG_FORCE_ACT)
		{
			//对方设备希望设置为ACT主机
			nLocalState = HA_STATE_STB;
			nLocalFlag = HA_FLAG_FORCE_STB;

			//将本设备设置为STB备机
			HA_STATE_GO_OOS;
			HA_STATE_GO_STB;
		}
		else
		{
			//对方设备希望设置为STB备机，本设备不作状态改变
			nLocalState = HA_STATE_ACT;
			nLocalFlag = HA_FLAG_FORCE_ACT;
		}
	}
	else if (nRunningState == HA_STATE_STB)
	{
		//本设备为备机
		if (pElectionReq->nFlags & HA_FLAG_FORCE_STB)
		{
			//对方设备希望设置为STB备机
			nLocalState = HA_STATE_ACT;
			nLocalFlag = HA_FLAG_FORCE_ACT;

			//将本设备设置为ACT主机
			HA_STATE_GO_OOS;
			HA_STATE_GO_ACT;
		}
		else
		{
			//对方设备希望设置为ACT主机，本设备不作状态改变
			nLocalState = HA_STATE_STB;
			nLocalFlag = HA_FLAG_FORCE_STB;
		}
	}
	else
	{
		//本设备为OOS主机
		if (pElectionReq->nFlags & HA_FLAG_FORCE_ACT)
		{
			//对方设备希望设置为ACT主机
			nLocalState = HA_STATE_STB;
			nLocalFlag = HA_FLAG_FORCE_STB;

			//将本设备设置为STB备机
			HA_STATE_GO_OOS;
			HA_STATE_GO_STB;
		}
		else if (pElectionReq->nFlags & HA_FLAG_FORCE_STB)
		{
			//对方设备希望设置为STB备机
			nLocalState = HA_STATE_ACT;
			nLocalFlag = HA_FLAG_FORCE_ACT;

			//将本设备设置为ACT主机
			HA_STATE_GO_OOS;
			HA_STATE_GO_ACT;
		}
		else 
		{
			//以本设备为主
			if (nLocalState == HA_STATE_ACT)
			{
				//本设备初始状态为主机
				nLocalState = HA_STATE_ACT;
				nLocalFlag = HA_FLAG_FORCE_ACT;

				//将本设备设置为ACT主机
				HA_STATE_GO_OOS;
				HA_STATE_GO_ACT;
			}
			else
			{
				//本设备初始状态为备机
				nLocalState = HA_STATE_STB;
				nLocalFlag = HA_FLAG_FORCE_STB;

				//将本设备设置为STB备机
				HA_STATE_GO_OOS;
				HA_STATE_GO_STB;
			}
		}
	}

	HaElectionResponse(nLocalState, nLocalPriority, nLocalFlag, pHaPktObj->nSequence, pHaHost);

	if( (pElectionReq->rNotifyMsg.nFaultState == HA_FAULT_HB_LOSS) && 
		(pElectionReq->rNotifyMsg.dwIPAddr != HaGetLocalIP()) )
	{
		//备机心跳检测判断主机故障，将备机设置为主机的情况
		HaSetInoutFaultNotifyMsg(&pElectionReq->rNotifyMsg);
	}

	return 0;
}

/***callback hook when rcv election response packet*/
int HaElectionRespCB(HaPktObject* pHaRespPktObj, HaHost* pHaHost)
{
	HaElectionResp* pElectionResp = (HaElectionResp*)pHaRespPktObj->chData;

	uint32_t dwLocalIp = HaGetLocalIP();
	HaState	 nLocalState = HaGetLocalState();
	uint8_t  nLocalPriority = HaGetLocalPriority();
	HaState  nRunningState = HaGetLocalRunningState();
	
	HA_LOG_DEBUG("resp_state: %s, resp_pririoty: %d, resp_flags: %d\n", ha_state_to_str(pElectionResp->nMyState),
		pElectionResp->nMyPriority, pElectionResp->nFlags);
	HA_LOG_DEBUG("local_state: %s, local_priority: %d, running_state: %s\n", ha_state_to_str(nLocalState),
		nLocalPriority, ha_state_to_str(nRunningState));

	/*****************************************************************************************
		if local init state is ACT and enable auto failback, local will run as ACT.
		if peer is FORCE_ACT, local will run as STB.
		if peer is FORCE_STB, local will run as ACT.
		if local running state is ACT,  just set  MY is ACT.
		otherwise, compare state, priroty,ip
	*****************************************************************************************/
	
	HaState nSwitchState = HA_STATE_STB;
	if (pElectionResp->nFlags & HA_FLAG_FORCE_ACT)
	{
		//对方设备希望设置为ACT主机
		nSwitchState = HA_STATE_STB;
	}
	else  if (pElectionResp->nFlags & HA_FLAG_FORCE_STB)
	{
		//对方设备希望设置为STB备机
		nSwitchState = HA_STATE_ACT;
	}
	else
	{
		uint32_t nPriority1 = nLocalState << 8 | nLocalPriority;
		uint32_t nPriority2 = pElectionResp->nMyState << 8 | pElectionResp->nMyPriority;

		if (nRunningState != HA_STATE_ACT)
		{
			if (nPriority1 > nPriority2)
			{
				nSwitchState = HA_STATE_ACT;
			}
			else if (nPriority1 < nPriority2)
			{
				nSwitchState = HA_STATE_STB;
			}
			else
			{
				if (dwLocalIp < pHaHost->rAddr.sin_addr.s_addr)
				{
					nSwitchState = HA_STATE_ACT;
				}
				else if (dwLocalIp > pHaHost->rAddr.sin_addr.s_addr)
				{
					nSwitchState = HA_STATE_STB;
				}
			}
		}
		else
		{
			nSwitchState = HA_STATE_ACT;
		}			
	}

	HA_LOG_DEBUG("switch_state: %s\n", ha_state_to_str(nSwitchState));

	if (nSwitchState != nRunningState)
	{
		HaSetRunningState(nSwitchState);
	}
		 
	return 0;
}

/***callback hook when local election request timeout*/
int HaElectionLocalReqTimeoutCB(HaPktObject* pHaPktObj, HaHost* pHaHost)
{
	//主机选举消息发送3秒钟以后没有收到应答，调用本函数
	HaElectionResp* pElectionResp = (HaElectionResp*)pHaPktObj->chData;
	
	HA_LOG_DEBUG("Flags: %d\n", pElectionResp->nFlags);
	if (pElectionResp->nFlags & HA_FLAG_FORCE_STB)
	{
		//设置为备机
		HA_STATE_GO_STB;
	}		
	else
	{
		//设置为主机
		HA_STATE_GO_ACT;
	}		

	return 0;
}

/***callback hook get wait timeout value for election request*/
uint32_t HaElectionTimeoutValue()
{
	return 3000; //ms
}

/***callback hook when send pkt error*/
int HaElectionSendtoErrCB(HaHost* pHaHost)
{
	return 0;
}

HaPacketHooks g_election_hooks =
{
	HA_PAYLOAD_ELECTION,
	"election hooks",
	HaElectionReqCB,
	HaElectionRespCB,
	HaElectionLocalReqTimeoutCB,
	HaElectionTimeoutValue,
	HaElectionSendtoErrCB
};

int HaElectionInit()
{
	if (ha_pkt_hooks_reg(&g_election_hooks) < 0)
	{
		return -1;
	}
		
	return 0;
}