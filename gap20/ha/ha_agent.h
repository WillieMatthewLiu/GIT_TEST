#ifndef _HA_AGENT_H_
#define _HA_AGENT_H_

#include "zebra.h"
#include "thread.h"
#include "vector.h"

#define HA_APP_MESSAGE_TYPE_REQUEST 1
#define HA_APP_MESSAGE_TYPE_RESPONE 2
#define HA_APP_MESSAGE_TYPE_NOTIFY  3

typedef struct _HaAppHandle
{
	struct list_head	node;
	uint32_t			nVtyServerCreated;
	uint32_t			dwAppModID;
	ha_event_cb			HaEventCB;
	ha_sync_recv_cb		HaSyncRcvCB;
	void*				pParam;
}HaAppHandle;

typedef struct _SlaveAddr
{
	uint16_t	nPort;
	char		ip[20];
}SlaveAddr;

typedef struct _HaAppControl
{
	int						nSocketFd;
	int						nFlag;
	pthread_mutex_t			handle_lock;
	struct list_head		handle_list;

	pthread_mutex_t			salveip_lock;
	vector					salveip_vector;

	struct thread_master*	base;
	struct thread*			read_thread;
	struct thread*			reconnect;
	pthread_t pid;
	HaAppMessage*			pRecvMsg;
	char				    chDataBuffer[HA_APP_MESSAGE_LEN_MAX];
}HaAppControl;

extern void haa_vty_add_hook();
extern int have_ha();

#endif