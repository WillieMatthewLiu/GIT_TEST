#ifndef _HA_STATE_MGR_H_
#define _HA_STATE_MGR_H_

#define HA_STATE_GO_OOS HaSetRunningState(HA_STATE_OOS)
#define HA_STATE_GO_ACT HaSetRunningState(HA_STATE_ACT)
#define HA_STATE_GO_STB HaSetRunningState(HA_STATE_STB)

typedef enum HaFaultState 
{
	HA_FAULT_NONE = 0,
	HA_FAULT_HB_LOSS
}HaFaultState;

typedef struct _HaStateMgr
{
	struct list_head	notify_head;	/* state change notify chain */
	pthread_mutex_t		lock;
	pthread_mutex_t		fault_lock;
	HaFaultNotifyMsg	rInOutMsg;		/* fault message send to inner or outer */
	HaFaultNotifyMsg	rElectionMsg;	/* fault message send with election pkt */
}HaStateMgr;

struct ha_state_change_cb 
{
	struct list_head node;
	int(*notify)(HAEvent, const char* pData, int nDataLen);
};

/**	for event check again @return 0 - skip this event notify*/
typedef int(*event_extern_check_func)(HAEvent e, void* ptr, int nLen);

int HaStateMgrInit();

HaErrorCode HaStateNotifyRegister(int(*notify)(HAEvent e, const char* pData, int nLen));

HaErrorCode HaSetRunningState(HaState nNewHaState);

void HaEventNotify(HAEvent nHaEvent, void* pData, int nLen);

HaFaultNotifyMsg* HaGetInoutFaultNotifyMsg();
void HaSetInoutFaultNotifyMsg(HaFaultNotifyMsg* pFaultNotifyMsg);

HaFaultNotifyMsg* HaGetElectionFaultNotifyMsg();
void HaSetElectionFaultNotifyMsg(HaFaultNotifyMsg* pFaultNotifyMsg);

void HaClearFaultMsg();

#endif