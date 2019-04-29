#include "app_common.h"
#include "util-lock.h"
#include "bitops.h"
#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_statemgr.h"
#include "ha_init.h"
#include "ha_election.h"
#include "ha_conf.h"

extern HaBaseMgr* g_pHaBaseMgr;
static HaStateMgr* g_pHaStateMgr;

event_extern_check_func event_extern_check[HA_EVENT_MAX] = {};

void HaEventNotifyAll(HAEvent nHaEvent, void* pDate, int nDataLen);

HaFaultNotifyMsg* HaGetInoutFaultNotifyMsg()
{
	return &g_pHaStateMgr->rInOutMsg;
}

void HaSetInoutFaultNotifyMsg(HaFaultNotifyMsg* pNotifyMsg)
{
	g_pHaStateMgr->rInOutMsg.dwIPAddr = pNotifyMsg->dwIPAddr;
	g_pHaStateMgr->rInOutMsg.nFaultState = pNotifyMsg->nFaultState;
	g_pHaStateMgr->rInOutMsg.nHaState = pNotifyMsg->nHaState;
}

HaFaultNotifyMsg* HaGetElectionFaultNotifyMsg()
{
	return &g_pHaStateMgr->rElectionMsg;
}

void HaSetElectionFaultNotifyMsg(HaFaultNotifyMsg* pNotifyMsg)
{
	g_pHaStateMgr->rElectionMsg.dwIPAddr = pNotifyMsg->dwIPAddr;
	g_pHaStateMgr->rElectionMsg.nFaultState = pNotifyMsg->nFaultState;
	g_pHaStateMgr->rElectionMsg.nHaState = pNotifyMsg->nHaState;		//将要设置的HA状态
}

void HaClearFaultMsg()
{
	memset(&g_pHaStateMgr->rInOutMsg, 0, sizeof(HaFaultNotifyMsg));
	memset(&g_pHaStateMgr->rElectionMsg, 0, sizeof(HaFaultNotifyMsg));
}

/*if heartbeat send OK, report STB up at ACT side*/
int DefaultEeventHbOnExternCheck(HAEvent nHaEvent, void* pDate, int nDataLen)
{
	HaEventNotifyAll(HA_EVENT_STB_UP, pDate, nDataLen);

	return HA_SUCCESS;
}

/*if heartbeat send LOSS, report STB down at ACT side,restart election at STB side*/
int DefaultEventHbLossExternCheck(HAEvent nHaEvent, void* pDate, int nDataLen)
{
	if (HaGetLocalRunningState() == HA_STATE_STB) 
	{
		//备机心跳检测判断主机故障，将备机设置为主机
		HA_LOG_DEBUG("DefaultEventHbLossExternCheck set HA_STATE_ACT\n");
		
		HaFaultNotifyMsg rNotifyMsg;
		memset(&rNotifyMsg, 0, sizeof(rNotifyMsg));
		
		rNotifyMsg.dwIPAddr = HaGetLocalIP();
		rNotifyMsg.nFaultState = HA_FAULT_HB_LOSS;
		rNotifyMsg.nHaState = HA_STATE_ACT;
		
		HaSetInoutFaultNotifyMsg(&rNotifyMsg);
		HaSetElectionFaultNotifyMsg(&rNotifyMsg);
		
		sem_post(g_pHaBaseMgr->ha_mutex);
	}
	else
	{
		//主机心跳检测判断备机故障，设置备机下线
		HaHost* pHaHost = (HaHost*)pDate;
		pHaHost->nOffTime = time(NULL); // STB host offline
		pHaHost->nOnTime = 0;

		HaEventNotifyAll(HA_EVENT_STB_DOWN, pDate, nDataLen);
	}
	
	return HA_SUCCESS;
}

/**Recv HA_EVENT_CONF_RECOVER event from act inner, tell us ha configuration has changed,
clear all hosts before rebuild socket.*/
int DefaultEventConfigRecoverExternCheck(HAEvent nHaEvent, void* pDate, int nDataLen)
{
	HaEventNotifyAll(nHaEvent, pDate, nDataLen);
	memset(g_pHaBaseMgr->rHaHostArray, 0, sizeof(HaHost) * 4);
	
	return HA_SUCCESS;
}

int HaStateMgrInit()
{
	g_pHaStateMgr = (HaStateMgr*)SCMalloc(sizeof(HaStateMgr));
	if (!g_pHaStateMgr)
	{
		return HA_ERROR_NOMEM;
	}
		
	memset(g_pHaStateMgr, 0, sizeof(HaStateMgr));
	INIT_LIST_HEAD(&g_pHaStateMgr->notify_head);

	mutex_init(&g_pHaStateMgr->lock);
	mutex_init(&g_pHaStateMgr->fault_lock);

	event_extern_check[HA_EVENT_HB_ON] = DefaultEeventHbOnExternCheck;
	event_extern_check[HA_EVENT_HB_LOSS] = DefaultEventHbLossExternCheck;
	event_extern_check[HA_EVENT_CONF_RECOVER] = DefaultEventConfigRecoverExternCheck;

	return HA_SUCCESS;
}

void HaEventNotifyAll(HAEvent nHaEvent, void* pDate, int nDataLen)
{
	struct ha_state_change_cb* pCBNode = NULL;

	mutex_lock(&g_pHaStateMgr->lock);
	list_for_each_entry(pCBNode, &g_pHaStateMgr->notify_head, node)
	{
		/* we just lock the list for each */
		mutex_unlock(&g_pHaStateMgr->lock);
		pCBNode->notify(nHaEvent, pDate, nDataLen);
		mutex_lock(&g_pHaStateMgr->lock);
	}
	mutex_unlock(&g_pHaStateMgr->lock);
}

void HaEventNotify(HAEvent nHaEvent, void* pDate, int nDataLen)
{
	if (event_extern_check[nHaEvent]) 
	{
		if (event_extern_check[nHaEvent](nHaEvent, pDate, nDataLen)) 
		{
			HA_LOG_ERROR("call extern heartbeat fail, will notify this evnet");
		}
		else
		{
			/* ignore current event */
			return;
		}
	}

	HaEventNotifyAll(nHaEvent, pDate, nDataLen);
}

/*************************************************************************************
	HA state change
	INIT-------->OOS<========>STB
				 | ^
				 | |
				 | |
				 V |
				 ACT
*************************************************************************************/
void HaStateChangeNotify(HaState nNewHaState, HaState nOldHaState)
{
	HAEvent nHaEvent = 0;
		
	if(nNewHaState == HA_STATE_ACT)
	{ 
		nHaEvent = HA_EVENT_GO_ACT;
	}		
	else if(nNewHaState == HA_STATE_STB)
	{
		nHaEvent = HA_EVENT_GO_STB;
	}		
	else if(nNewHaState == HA_STATE_OOS)
	{
		nHaEvent = HA_EVENT_GO_OOS;
	}		

	struct in_addr rLocalAddr;
	rLocalAddr.s_addr = HaGetLocalIP();
	
	char chLocalIP[20] = { 0 };
	inet_ntop(AF_INET, &rLocalAddr, chLocalIP, 20);
	
	HaEventNotify(nHaEvent, chLocalIP, strlen(chLocalIP) + 1);
}

HaErrorCode HaSetRunningState(HaState nNewHaState)
{
	HaBaseMgr* pHaBaseMgr = g_pHaBaseMgr;

	HA_LOG_DEBUG("set %s state\n", ha_state_to_str(nNewHaState));

	mutex_lock(&pHaBaseMgr->state_lock);
	if (pHaBaseMgr->nHaState != nNewHaState)
	{
		HaState nOldHaState = pHaBaseMgr->nHaState;
		pHaBaseMgr->nHaState = nNewHaState;
		mutex_unlock(&pHaBaseMgr->state_lock);
		
		HaStateChangeNotify(nNewHaState, nOldHaState);
	}
	else
	{
		mutex_unlock(&pHaBaseMgr->state_lock);
	}
		
	return HA_SUCCESS;
}

HaErrorCode HaStateNotifyRegister(int(*pNotifyCB)(HAEvent nHaEvent, const char* pDate, int nDataLen))
{
	struct ha_state_change_cb* pCBNode = (struct ha_state_change_cb*)SCMalloc(sizeof(struct ha_state_change_cb));
	if (NULL == pCBNode)
	{
		return HA_ERROR_NOMEM;
	}
		
	memset(pCBNode, 0, sizeof(struct ha_state_change_cb));
	pCBNode->notify = pNotifyCB;
	
	mutex_lock(&g_pHaStateMgr->lock);
	list_add_tail(&pCBNode->node, &g_pHaStateMgr->notify_head);
	mutex_unlock(&g_pHaStateMgr->lock);

	return HA_SUCCESS;
}