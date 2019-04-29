#include "zebra.h"

#include "linklist.h"
#include "command.h"
#include "prefix.h"
#include "zclient.h"

#include "app_common.h"

#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_statemgr.h"

static struct zclient* zclient;

struct ipm_mgr 
{
	pthread_t pid;
	int is_active;
	struct event_base* pIpmEventBase;
	struct event* pBackgroudEvent;;
	struct event* garp_refresh;
}_ipm_mgr;

/* Inteface link up message processing. */
int ipm_interface_up(int command, struct zclient *zclient, zebra_size_t nLength, vrf_id_t vrf_id)
{
	/* zebra_interface_state_read() updates interface structure in iflist. */
	struct stream* s = zclient->ibuf;
	struct interface* ifp = zebra_interface_state_read(s, vrf_id);
	if (ifp == NULL)
	{
		return 0;
	}
	
	return 0;
}

/* Inteface link down message processing. */
int ipm_interface_down(int command, struct zclient *zclient, zebra_size_t nLength, vrf_id_t vrf_id)
{
	/* zebra_interface_state_read() updates interface structure in iflist. */
	struct stream* s = zclient->ibuf;
	struct interface* ifp = zebra_interface_state_read(s, vrf_id);
	if (ifp == NULL)
	{
		return 0;
	}
	
	return 0;
}

/* Inteface addition message from zebra. */
int ipm_interface_add(int command, struct zclient *zclient, zebra_size_t nLength, vrf_id_t vrf_id)
{
	struct interface* ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (ifp == NULL)
	{
		return 0;
	}
	
	return 0;
}

int ipm_interface_delete(int command, struct zclient *zclient, zebra_size_t nLength, vrf_id_t vrf_id)
{
	struct stream *s = zclient->ibuf;
	
	/*  zebra_interface_state_read() updates interface structure in iflist */
	struct interface *ifp = zebra_interface_state_read(s, vrf_id);
	if (ifp == NULL)
	{
		return 0;
	}

	if (if_is_up(ifp)) 
	{
	}

	ifp->ifindex = IFINDEX_INTERNAL;

	return 0;
}

int ipm_interface_address_add(int command, struct zclient *zclient,
	zebra_size_t nLength, vrf_id_t vrf_id)
{
	struct connected* c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, zclient->ibuf, vrf_id);
	if (c == NULL)
	{
		return 0;
	}
		
	struct prefix* p = c->address;
	if (p->family == AF_INET6)
	{
	}

	return 0;
}

int ipm_interface_address_delete(int command, struct zclient *zclient, zebra_size_t nLength, vrf_id_t vrf_id)
{
	struct connected* ifc = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, zclient->ibuf, vrf_id);
	if (ifc)
	{
		struct prefix* p = ifc->address;

		if (p->family == AF_INET6)
		{
		}
		
		connected_free(ifc);
	}

	return 0;
}

static void ipm_zebra_connected(struct zclient* zclient)
{
	zclient_send_requests(zclient, VRF_DEFAULT);
}

void ipm_zebra_init(struct thread_master* master)
{
	/* Allocate zebra structure. */
	zclient = zclient_new(master);
	zclient_init(zclient, ZEBRA_ROUTE_HA);
	
	zclient->zebra_connected = ipm_zebra_connected;
	zclient->interface_up = ipm_interface_up;
	zclient->interface_down = ipm_interface_down;
	zclient->interface_add = ipm_interface_add;
	zclient->interface_delete = ipm_interface_delete;
	zclient->interface_address_add = ipm_interface_address_add;
	zclient->interface_address_delete = ipm_interface_address_delete;
}

static int interface_config_write(struct vty *vty)
{
	return 0;
}

static struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if-%s)# ",
  1 /* VTYSH */
};

void ipm_if_init()
{
	vrf_init();

	/* Install interface node. */
	install_node(&interface_node, interface_config_write);

	/* Install commands. */
	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);
	
	install_default(INTERFACE_NODE);
	install_element(INTERFACE_NODE, &interface_desc_cmd);
	install_element(CONFIG_NODE, &interface_outer_cmd);
	install_element(INTERFACE_NODE, &no_interface_desc_cmd);
}

void ipm_garp_send(int nSocketFd, short flags, void *arg)
{
	struct listnode* node;
	struct interface* ifp;
	struct ipm_mgr* mgr = arg;
	HaSysConfig* pSysConfig = HaGetConfig();

	for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp))
	{
		if (ifp->name[0] == 'o')
		{
			/* run at inner, will skip outer interface */
			continue;
		}

		send_link_update(ifp, pSysConfig->nGarpRepeat);
	}
}

void ipm_background(evutil_socket_t nSocketFd, short nFlag, void* pParam)
{
}

void* ipm_event_loop(void* pArg)
{
	struct ipm_mgr* pMgr = pArg;

	HA_LOG_DEBUG("ha_ipm_cmgr running\n");

	event_base_loop(pMgr->pIpmEventBase, 0);

	return NULL;
}

static int HaStateChangeCB(HAEvent nHaEvent, const char *pData, int nDataLen)
{
	HaSysConfig* pSysConfig = HaGetConfig();
	struct ipm_mgr* mgr = &_ipm_mgr;
	
	switch (nHaEvent)
	{
	case HA_EVENT_GO_ACT:			//通知应用模块进入Active状态,发送GARP包
		ipm_garp_send(-1, 0, mgr);
		if (mgr->garp_refresh)
		{
			event_del(mgr->garp_refresh);
			event_free(mgr->garp_refresh);
		}
		
		mgr->garp_refresh = event_new(mgr->pIpmEventBase, -1, EV_TIMEOUT | EV_PERSIST, ipm_garp_send, mgr);
		event_add(mgr->garp_refresh, &pSysConfig->rGarpRefreshTimer);
		break;
		
	case HA_EVENT_GO_STB:			//通知应用模块进入Standby状态，停止发送GARP包
		if (mgr->garp_refresh)
		{
			event_del(mgr->garp_refresh);
			event_free(mgr->garp_refresh);
			mgr->garp_refresh = NULL;
		}
		break;
		
	default:
		break;
	}
	
	return 0;
}

int ipm_init()
{
	struct ipm_mgr* mgr = &_ipm_mgr;
	memset(mgr, 0, sizeof(struct ipm_mgr));

	evthread_use_pthreads();
	
	mgr->pIpmEventBase = event_base_new();
	mgr->pBackgroudEvent = event_new(mgr->pIpmEventBase, -1, EV_READ | EV_PERSIST, ipm_background, NULL);
	event_add(mgr->pBackgroudEvent, NULL);

	pthread_create(&mgr->pid, NULL, ipm_event_loop, mgr);

	HaStateNotifyRegister(HaStateChangeCB);

	return 0;
}