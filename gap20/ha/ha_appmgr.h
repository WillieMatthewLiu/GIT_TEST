#ifndef _HA_APP_MGR_H_
#define _HA_APP_MGR_H_

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

/* HA Agent client */
typedef struct _HaAgentClient 
{
	struct list_head	node;
	int					nSocketFd;									/* app client fd */
	uint32_t			dwAppModID;
	
	struct bufferevent* pBufferEvent;
	struct evbuffer*	pRecvBuffer;
}HaAgentClient;

struct HaSyncServer 
{
	int nSyncFd;
	int nServerSockFd;						/* data sync channel use TCP protocol, this is server socket */
	
	struct event_base* pSyncEventBase;
	struct event* pBackgroudEvent;	
	struct event* pAcceptEvent;				/* used for accept */	
	
	struct bufferevent* pBufferEvent;		/* userd for server read */
	struct evbuffer* pRecvBuffer;
};

typedef struct _HaAppMgr
{
	int					nSocketFd;			/* listen socket for Application manager, base on HA_APP_MGR_PATH */
	struct event_base*	pAppEventBase;		/* event base for appmgr */
	struct event*		pRecvEvent;			/* read event, base on sock */
	pthread_t			evthread;

	pthread_rwlock_t	lock;
	struct list_head	app_list;			/* register application list */
}HaAppMgr;

/**	HA application management initilization.*/
int ha_app_mgr_init();
HaAgentClient* ha_app_get(uint32_t dwAppModID);

int ha_app_send(HaAgentClient* pAgentClient, HaAppMessage* pData, int nDataLen);

struct event* appmgr_add_read(int nSocketFd, short ev, event_callback_fn cb, void* pArgs);
struct bufferevent* appmgr_add_bev(evutil_socket_t nSocketFd, bufferevent_data_cb datacb,
	bufferevent_data_cb writecb, bufferevent_event_cb eventcb, struct timeval* tv, void* pArgs);

#endif