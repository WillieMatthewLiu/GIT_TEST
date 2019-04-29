#include <zebra.h>
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "vrf.h"
#include "vty.h"
#include "db_mysql.h"
#include "bitops.h"

#include "app_common.h"
#include "gapconfig.h"
#include "oscall.h"
#include "sockmgr.h"
#include "servers.h"
#include "serialize.h"
#include "pktfilter.h"
#include "nlkernel.h"
#include "usertable.h"
#include "gap_ctl.h"
#include "util-config.h"
#include "config.h" // for SYSCONFDIR
#include "db_agent.h"
#include "ipt_ctl.h"
#include "gap_ipt_log.h"
#include "main_inouter.h"
#include "thread.h"
#include "swe_ver.h"
#include "dbsynctask.h"
#include "cmd_common.h"
#include "gap_traffic_est.h"
#include "appsession.h"

extern void zebra_init(struct thread_master *master);

extern struct thread_master *master;

#define GETSCFG(key, def) config_getstr("inouter", key, def)
#define GETICFG(key, def) config_getint("inouter", key, def)

int g_pciready = 0;


int tlv_init_from_appsession(struct app_session *session, struct tlvbox *obj, int cmd)
{
	tlvbox_put_uint32(obj, TLV_COMM_FWDCMD, cmd);
	tlvbox_put_uint32(obj, TLV_COMM_SESSIONID, session->id);
	tlvbox_put_uint32(obj, TLV_COMM_DIRECTION, (session->flthdr.svr == NULL)); // req: 0, resp: 1
	tlvbox_put_uint32(obj, TLV_COMM_SERVERID, session->filter->svrid);
	return 0;
}

//////////////////////////////////////////////////////////////////////////
// fwdobj cross multit thread
enum SESSION_CMD
{
	SSCMD_CLIIN,
	SSCMD_CONNOK,
	SSCMD_CLOSE
};
struct mgr_fwd_obj
{
	enum SESSION_CMD cmd;
	uint32_t sessionid;	// SSCMD_CLOSE、SSCMD_CLIIN、SSCMD_CONNOK

	evutil_socket_t fd;	// SSCMD_CLIIN、SSCMD_CONNOK

	struct server *svr;	// SSCMD_CLIIN
	char *cliinfo;		// SSCMD_CLIIN
};
void forwardobj_free(struct mgr_fwd_obj *obj)
{
	if (obj == NULL)
		return;
	if (obj->cliinfo)
		SCFree(obj->cliinfo);
	SCFree(obj);
}

//////////////////////////////////////////////////////////////////////////
void mainmgr_onsockdata(const void *buff, size_t len, void *args);
void mainmgr_onsockwrite(size_t remainlen, void *args);
void mainmgr_oncliin(evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args);
void mainmgr_onconnok(evutil_socket_t fd, void *args);
void mainmgr_onctlobj(const void *buff, size_t bufflen, void *args);
void mainmgr_onmgrobj(const void *buff, size_t bufflen, void *args);
void mainmgr_onpcidata(const void *buff, size_t bufflen, void *args);
void mainmgr_onpciwrite(size_t remainlen, void *args);
void mainmgr_oncapdata(const void *buff, size_t bufflen, void *args);
int filter_sendto_socket(struct filter_header *flthdr, const void *buff, size_t bufflen);
int filter_sendto_forward(struct filter_header *flthdr, const void *buff, size_t bufflen);
int filter_add_server(struct filter_header *hdr, struct server *svr);
int filter_remove_server(struct filter_header *hdr, struct server *svr);
int filter_sendto_pcap(struct filter_header *flthdr, const void *buff, size_t bufflen);
void mainmgr_onctl_close(struct app_session *session, struct mgr_fwd_obj *fwdobj);
void udp_data_oncli(const void *buff, size_t len, evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args);
void udp_data_onsvr(const void *buff, size_t len, evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args);
int udp_start_server(struct server *svr, ONUDPDATA_CB cb);
int udp_start_client(const char *localaddr, uint16_t localport, ONUDPDATA_CB cb, void *args);
int udp_stop_server(struct server *svr);
int udp_port_range_config();
uint16_t udp_freeport_get();
void udp_freeport_put(uint16_t udp_port);

//////////////////////////////////////////////////////////////////////////
#include "gap_stgy.h"

int handle_rule_on_tvldata(struct tlvbox *tlv, struct app_session *session)
{
	void *private = session->flthdr.private;

	/* 获取服务ID、命令码和方向 */
	struct tlvhdr *hdsvrid = tlvbox_find(tlv, TLV_COMM_SERVERID);
	struct tlvhdr *hdfwdcmd = tlvbox_find(tlv, TLV_COMM_FWDCMD);

	if (hdfwdcmd == NULL || hdsvrid == NULL) {
		SCLogInfo("Call tlvbox_find(%p, %p)%d failed.", hdfwdcmd, hdsvrid, tlv_get_uint32(hdfwdcmd));
		return -1;
	}

	uint32_t svrid = tlv_get_uint32(hdsvrid);
	uint32_t fwdcmd = tlv_get_uint32(hdfwdcmd);

	/* 处理过滤规则和安全校验 */
	switch (fwdcmd)
	{
	case _FWDCMD_CLI_IN:
	{
		/* 获取条件信息 */
		struct tlvhdr *hdstrdata = tlvbox_find(tlv, TLV_COMM_STRDATA);
		if (hdstrdata == NULL) 
		{
			SCLogInfo("Call tlvbox_find(TLV_COMM_STRDATA) faild.");
			return -1;
		}
		char *strdata = tlv_get_string(hdstrdata);
		struct acl_data *ad = SCMalloc(sizeof(struct acl_data));
		if (ad == NULL) 
		{
			SCLogInfo("Call SCMalloc failed.");
			return -1;
		}
		if (get_acl_data(strdata, ad))
		{
			SCLogInfo("Call get_acl_data failed.");
			SCFree(ad);
			return -1;
		}
		ad->svrid = svrid;

		/* 保存条件信息*/
		if (private != NULL) 
		{
			SCFree(private);
		}
		private = ad;
		session->flthdr.private = ad;

		/* 回调策略校验函数 */
		char rule[1024] = "";
		struct acl_data *data = (struct acl_data *)private;
		const char *proto = proto_strfromid(ad->svrid);
		int ret = stgy_check_rule(private, rule, sizeof(rule));
		int protocol = session->flthdr.tcp ? 6 : 17;
		if (ret == -1) 
		{
			SCLogInfo("blocking svrid=%d.", svrid);
			/*记录访问阻断日志*/
			INSERT_ACCESSAUDIT_LOG(session->auto_id, data->c_sip, data->c_dip, protocol, data->sport, data->dport, proto, data->user, "none", l_critical, rule, "访问阻断", 0, "危险的连接，被阻断!");
			return -1;
		}
		else if (ret == 1)
		{
			SCLogInfo("warning svrid=%d.", svrid);
			/*记录访问告警日志*/
			INSERT_ACCESSAUDIT_LOG(session->auto_id, data->c_sip, data->c_dip, protocol, data->sport, data->dport, proto, data->user, "none", l_warn, rule, "警告", 0, "危险的连接, 警告!");
		}
		else 
		{
			/*插入会话日志*/
			INSERT_SESSION(session);
		}
		break;
	}
	default:
		break;
	}

	return 0;
}

int handle_rule_on_cliin(char *strdata, struct app_session *session)
{
	void *private = session->flthdr.private;
	uint32_t svrid = session->flthdr.svr->id;

	/* 处理过滤规则和安全校验 */
	struct acl_data *ad = SCMalloc(sizeof(struct acl_data));
	if (ad == NULL) 
	{
		SCLogInfo("Call SCMalloc failed.");
		return -1;
	}
	if (get_acl_data(strdata, ad)) 
	{
		SCLogInfo("Call get_acl_data failed.");
		SCFree(ad);
		return -1;
	}
	ad->svrid = svrid;

	/* 保存条件信息*/
	if (private != NULL) {
		SCFree(private);
	}
	private = ad;
	session->flthdr.private = ad;

	/* 回调策略校验函数 */
	char rule[1024] = "";
	struct acl_data *data = (struct acl_data *)private;
	const char *proto = proto_strfromid(ad->svrid);
	int ret = stgy_check_rule(private, rule, sizeof(rule));
	int protocol = session->flthdr.tcp ? 6 : 17;
	if (ret == -1) 
	{
		SCLogInfo("blocking svrid=%d.", svrid);
		/*记录访问阻断日志*/
		INSERT_ACCESSAUDIT_LOG(session->auto_id, data->c_sip, data->c_dip, protocol, data->sport, data->dport, proto, data->user, "none", l_critical, rule, "访问阻断", 0, "危险的连接，被阻断!");
		return -1;
	}
	else if (ret == 1)
	{
		SCLogInfo("warning svrid=%d.", svrid);
		/*记录访问告警日志*/
		INSERT_ACCESSAUDIT_LOG(session->auto_id, data->c_sip, data->c_dip, protocol, data->sport, data->dport, proto, data->user, "none", l_warn, rule, "警告", 0, "危险的连接, 警告!");
	}
	else
	{
		/*插入会话日志*/
		INSERT_SESSION(session);
	}

	return 0;
}

//////////////////////////////////////////////////////////////////////////
// conn/session manager
#define MGRCNT 4
static struct connectionmgr *g_connmgr = NULL;
static struct sessionmgr *g_sessionmgr[MGRCNT] = { 0 };
static struct sessionmgr *g_kernelmgr = NULL;
static evutil_socket_t g_sessionctl[MGRCNT] = { 0 };
static evutil_socket_t g_sessionctl_r[MGRCNT] = { 0 };
int mgr_free();
int mgr_init()
{
	int ret;

	for (int i = 0; i < MGRCNT; i++)
	{
		evutil_socket_t tmp[2];
		ret = evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, tmp);
		if (ret != 0)
		{
			mgr_free();
			return -1;
		}
		g_sessionctl_r[i] = tmp[0];
		g_sessionctl[i] = tmp[1];

		g_sessionmgr[i] = sessionmgr_new();
		if (g_sessionmgr[i] == NULL)
		{
			mgr_free();
			return -1;
		}

		sessionmgr_fdadd(g_sessionmgr[i], g_sessionctl_r[i], mainmgr_onctlobj, NULL, NULL, NULL);
	}
	g_kernelmgr = g_sessionmgr[0];

	sessionmgr_setcpu(g_sessionmgr[0], 0);
	sessionmgr_setcpu(g_sessionmgr[1], 1);
	sessionmgr_setcpu(g_sessionmgr[2], 2);
	sessionmgr_setcpu(g_sessionmgr[3], 3);

	g_connmgr = connmgr_new();
	if (g_connmgr == NULL)
	{
		mgr_free();
		return -1;
	}

	return 0;
}
int mgr_free()
{
	if (g_connmgr != NULL)
		connmgr_free(g_connmgr);
	g_connmgr = NULL;

	for (int i = 0; i < MGRCNT; i++)
	{
		if (g_sessionmgr[i] == NULL)
			continue;

		sessionmgr_fdclose(g_sessionmgr[i], g_sessionctl_r[i]);
		sessionmgr_free(g_sessionmgr[i]);
		g_sessionmgr[i] = NULL;
	}
	g_kernelmgr = NULL;
	return 0;
}

int sessionmap_postclose(struct app_session *session)
{
	struct mgr_fwd_obj *fwdobj = NULL;

	int ok = 0, ret;
	do
	{
		if (session->mgr == sessionmgr_current())
		{
			mainmgr_onctl_close(session, NULL);
			ok = 1;
			break;
		}

		// create fwdobj, process on business thread
		fwdobj = SCMalloc(sizeof(struct mgr_fwd_obj));
		if (fwdobj == NULL)
			break;
		memset(fwdobj, 0, sizeof(*fwdobj));
		fwdobj->cmd = SSCMD_CLOSE;
		fwdobj->sessionid = session->id;

		evutil_socket_t forwardsock = g_sessionctl[sessionmgr_getid(session->mgr)];
		ret = socket_syncsend(forwardsock, &fwdobj, sizeof(fwdobj));
		if (ret == -1)
			break;

		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (fwdobj != NULL)
			SCFree(fwdobj);
	}

	if (ok == 0)
		return -1;
	return 0;
}

//////////////////////////////////////////////////////////////////////////
// kernel
#include "nlkernelmsg.h"
static evutil_socket_t g_kernelfd;
struct app_session g_kernelsession;
int kernel_init()
{
	int ret, addok = 0, ok = 0;
	do
	{
		nlkernel_encrypt_enable();
		g_kernelfd = nlkernel_init();
		if (g_kernelfd == -1)
		{
			SCLogInfo("nlkernel_init return -1");
			break;
		}
			
		struct app_session *session = &g_kernelsession;
		memset(session, 0, sizeof(*session));
		session->id = 0;
		session->mgr = g_kernelmgr;
		session->filter = pktfilter_get(SVR_ID_PCAP);
		session->flthdr.sessionid = session->id;
		session->flthdr.fwdcb = filter_sendto_forward;
		session->flthdr.reqcb = filter_sendto_pcap;
		session->flthdr.respcb = filter_sendto_pcap;
		session->flthdr.svr_add_cb = filter_add_server;
		session->flthdr.svr_remove_cb = filter_remove_server;
		session->flthdr.tlv_in = NULL;
		session->flthdr.tlv_out = tlvbox_create(0);

		ret = sessionmgr_fdadd(g_kernelmgr, g_kernelfd, mainmgr_oncapdata, NULL, NULL, session);
		if (ret != 0)
		{
			printf("%s %s(%d) ret == 0\n", __FILE__, __FUNCTION__, __LINE__);
			break;
		}
			
		addok = 1;

		ret = sessionmap_put(session);
		if (ret != 0)
		{
			printf("%s %s(%d) ret == 0\n", __FILE__, __FUNCTION__, __LINE__);
			break;
		}			

		ok = 1;
	} while (0);

	if (ok == 0)
	{
		printf("%s %s(%d) ok == 0\n", __FILE__, __FUNCTION__, __LINE__);	

		if (addok == 1)
			sessionmgr_fdclose(g_kernelmgr, g_kernelfd);

		if (g_kernelfd != -1)
			closesocket(g_kernelfd);
		g_kernelfd = -1;
	}

	return (ok == 1) ? 0 : -1;
}
int kernel_free()
{
	nlkernel_free();

	if (g_kernelfd > 0)
		sessionmgr_fdclose(g_kernelmgr, g_kernelfd);
	g_kernelfd = 0;
	return 0;
}

//////////////////////////////////////////////////////////////////////////
// PCI channel
#define PCI_PAUSE_SIZE 100 * 1024 * 1024	// 100M
static evutil_socket_t g_pci_fd[MGRCNT] = { 0 };
static struct evbuffer *g_pci_buff[MGRCNT];
static int g_pci_pause[MGRCNT] = { 0 };
void pcidrv_onouterin(evutil_socket_t clifd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args)
{
	int i;
	for (i = 0; i < MGRCNT; i++)
	{
		if (g_pci_fd[i] == 0)
			break;
	}
	if (i == MGRCNT)
	{
		char *err = "invalid client";
		socket_syncsend(clifd, err, (int)strlen(err)); os_sleep(1);
		closesocket(clifd);
		return;
	}

	g_pci_fd[i] = clifd;
	sessionmgr_fdadd(g_sessionmgr[i], g_pci_fd[i], mainmgr_onpcidata, mainmgr_onpciwrite, NULL, g_sessionmgr[i]);
	g_pci_buff[i] = evbuffer_new();
}

int pcidrv_free();
int pcidrv_init()
{
	if (RUN_AS_INNER())
	{
		if (connmgr_addlistener(g_connmgr, INNER_DEFAULT_IP_STR, 20001, pcidrv_onouterin, NULL) != 0)
			return -1;
		return 0;
	}

	if (RUN_AS_OUTER())
	{

		for (int i = 0; i < MGRCNT; i++)
		{
			g_pci_fd[i] = connmgr_syncconnect(INNER_DEFAULT_IP_STR, 20001);
			if (g_pci_fd[i] == -1)
			{
				SCLogInfo("connect %s:%d by failed", INNER_DEFAULT_IP_STR, 20001);
				perror("bind error");

				return -1;
			}

			g_pci_buff[i] = evbuffer_new();
			sessionmgr_fdadd(g_sessionmgr[i], g_pci_fd[i], mainmgr_onpcidata, mainmgr_onpciwrite, NULL, g_sessionmgr[i]);
		}
	}
	return 0;
}
int pcidrv_free()
{
	for (int i = 0; i < MGRCNT; i++)
	{
		closesocket(g_pci_fd[i]);
		g_pci_fd[i] = -1;
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////
// inititalize servers
int svrs_free();
int svrs_init()
{
	int ret;
	struct server *svr;

	do
	{
		//////////////////////////////////////////////////////////////////////////
		svr = server_new(SVR_ID_SSL, "ssl server", "0.0.0.0", 9001, NULL, 0);
		if (svr == NULL)
			break;
		svr->type = SVR_TYPE_INTERNAL_SSL;

		ret = connmgr_addlistener(g_connmgr, svr->localip, svr->localport, mainmgr_oncliin, svr);
		if (ret != 0)
			break;

		return 0;

	} while (0);

	if (svr != NULL)
		server_free(svr);
	return ret;
}
int svrs_free()
{
	// TODO：free ssl server
	return 0;
}

struct filter_header* sessionmap_gethdr_fromid(uint32_t sessionid)
{
	struct app_session *session = sessionmap_get(sessionid);
	if (session == NULL)
		return NULL;
	return &session->flthdr;
}

int get_sockfd_byhdr(struct filter_header *hdr)
{
	struct app_session *session = OFFSET_OBJECT(hdr, app_session, flthdr);
	return session->fd;
}

void natserver_checktimeout()
{
#define SERVER_CHECK_COUNT 500
	struct array *arr = array_init(SERVER_CHECK_COUNT);

	time_t now; time(&now);

	gapconfig_lock();
	int breakall = 0;
	for (int i = 0; i < array_count(g_gapcfg->eths); i++)
	{
		struct interface *ifp = array_getat(g_gapcfg->eths, i);
		for (int j = 0; j < array_count(if_get_routes(ifp)); j++)
		{
			struct route_item *route = array_getat(if_get_routes(ifp), j);

			struct server templ = { 0 }; templ.type = SVR_TYPE_INTERNAL_NAT;
			struct array *svrs = gapconfig_findserver(route, &templ);
			if (svrs == NULL)
				continue;

			for (int k = 0; k < array_count(svrs); k++)
			{
				struct server *svr = array_getat(svrs, k);

				if (svr->sessioncount > 0 || now - svr->livetime < g_gapcfg->timeout_session)
					continue;

				array_add(arr, svr);
				if (array_count(arr) >= SERVER_CHECK_COUNT)
				{
					breakall = 1;
					break;
				}
			}
			array_free(svrs);

			if (breakall)
				break;
		}

		if (breakall)
			break;
	}

	for (int i = 0; i < array_count(arr); i++)
	{
		struct server *svr = array_getat(arr, i);
		delnat(svr->dstip, svr->dstport, svr->localip, svr->localport);
		connmgr_removelistener(g_connmgr, svr->localip, svr->localport);
		gapconfig_removeserver(svr->route, svr);
		server_free(svr);
	}
	gapconfig_unlock();

	array_free(arr);
}

// vty helper code
int vtyhlp_svrclosefree(struct array *arr)
{
	int ret;
	for (int i = 0; i < array_count(arr); i++)
	{
		struct server *svr = array_getat(arr, i);
		if (SVRID_IS_UDP_FAMILY(svr->id))
			ret = udp_stop_server(svr);
		else
			ret = connmgr_removelistener(g_connmgr, svr->localip, svr->localport);
		if (ret != 0)
			goto ERR;

		ret = sessionmap_freebysvr(svr);
		if (ret != 0)
			goto ERR;

		struct route_item *route = svr->route;
		if (route != NULL)
		{
			// server is create by nat, so free nat map
			if (route->in_port == 0)
				delnat(svr->dstip, svr->dstport, svr->localip, svr->localport);
			gapconfig_removeserver(route, svr);
		}
		server_free(svr);
	}
	return 0;
ERR:
	return -1;
}
int vtyhlp_closeall_byroute(struct route_item *route)
{
	vtyhlp_svrclosefree(route->servers);
	return 0;
}
int vtyhlp_closeall_byaddr(struct interface *ifp, const char *localip)
{
	struct array *svrs = gapconfig_getserver_byaddr(ifp, localip);
	if (svrs == NULL)
		return -1;
	vtyhlp_svrclosefree(svrs);
	array_free(svrs);
	return 0;
}

int vtyhlp_applyroute(struct route_item *route)
{
	int ret;
	char dip[20];
	struct server *svr = NULL;
	struct interface *ifp = NULL;
	struct gap_route *vtyroute = route->vtyroute;

	ifp = gapconfig_get_if_by_name(route->vtyroute->inif);
	if (ifp == NULL)
	{
		SCLogError("on vtyhlp_applyroute, gapconfig_get_if_by_name failed: %s", route->vtyroute->inif);
		return -1;
	}

	enum SVR_ID id = server_idfromstr(route->vtyroute->proto);
	if (id == _SVR_ID_NONE)
	{
		SCLogError("on vtyhlp_applyroute, invalid protocol string; %s", route->vtyroute->proto);
		return -1;
	}

	addr2str(htonl(vtyroute->dip_group->ir[0].first_ip), dip);
	svr = server_new(id, route->vtyroute->name, route->vtyroute->entryip, atoi(vtyroute->inport), dip, atoi(vtyroute->dport));
	if (svr == NULL)
	{
		SCLogError("on vtyhlp_applyroute, alloc server failed");
		return -1;
	}

	if (SVRID_IS_UDP_FAMILY(id))
	{
		ret = udp_start_server(svr, udp_data_onsvr);
	}		
	else
	{
		ret = connmgr_addlistener(g_connmgr, svr->localip, svr->localport, mainmgr_oncliin, svr);
	}
	
	if (ret != 0)
	{		
		SCLogError("on vtyhlp_applyroute, add server listener failed, %s:%d, errno: %d, errstr: %s", svr->localip, svr->localport, errno, strerror(errno));
		if (errno == EADDRINUSE)
		{			
		}
		server_free(svr);
		
		return -1;	
	}
	
	ret = gapconfig_addserver(route, svr);
	if (ret != 0)
	{
		server_free(svr);
		SCLogError("on vtyhlp_applyroute, add server failed");
		return -1;
	}

	return 0;
}

int vtyhlp_sendiptokernel(const char *ifname, const char *ip, int remove)
{
	struct nl_kernel_msg msg;
	msg.type = NLCMD_IP;
	msg.op = (remove == 0) ? NLOP_ADD : NLOP_REMOVE;
	msg.data.localip.ip = inet_addr(ip);
	strncpy(msg.data.localip.ifname, ifname, sizeof(msg.data.localip.ifname));
	int ret = nlkernel_sendmsg(&msg);
	return ret;
}
int vtyhlp_enable_arpicmp(const char *ifname, int enable)
{
	struct interface *ifp = if_get_by_name(ifname);
	if (ifp == NULL)
		return -1;

	int n = ifp->ifindex;
	if (n == -1 || n >= MAX_ETH_COUNT)
		return -1;

	static int arpicmp_enabled[MAX_ETH_COUNT] = { 0 };
	if (enable == 1 && arpicmp_enabled[n] == 1)
		return 0;
	if (enable == 0 && arpicmp_enabled[n] == 0)
		return 0;

	int ok = 0;
	do
	{
		{
			struct nl_kernel_msg msg;
			msg.type = NLCMD_PROTO;
			msg.op = enable ? NLOP_ADD : NLOP_REMOVE;
			msg.data.proto.layer = 2;
			msg.data.proto.protocol = 0x0806;	// ARP
			strncpy(msg.data.proto.ifname, ifp->name, sizeof(msg.data.proto.ifname));
			if (nlkernel_sendmsg(&msg) != 0)
				break;
		}

		{
			struct nl_kernel_msg msg;
			msg.type = NLCMD_PROTO;
			msg.op = enable ? NLOP_ADD : NLOP_REMOVE;
			msg.data.proto.layer = 3;
			msg.data.proto.protocol = IPPROTO_ICMP;	// ICMP
			strncpy(msg.data.proto.ifname, ifp->name, sizeof(msg.data.proto.ifname));
			if (nlkernel_sendmsg(&msg) != 0)
				break;
		}

		ok = 1;
	} while (0);

	if (ok == 0)
		return -1;

	arpicmp_enabled[n] = enable;
	return 0;
}
int vtyhlp_enable_udp(const char *ifname, int enable)
{
	struct interface *ifp = if_lookup_by_name(ifname);
	if (ifp == NULL)
		return -1;

	int n = ifp->ifindex;
	if (n == -1 || n >= MAX_ETH_COUNT)
		return -1;

	static int udp_enabled[MAX_ETH_COUNT] = { 0 };
	if (enable == 1 && udp_enabled[n] == 1)
		return 0;
	if (enable == 0 && udp_enabled[n] == 0)
		return 0;

	int ok = 0;
	do
	{
		struct nl_kernel_msg msg;
		msg.type = NLCMD_PROTO;
		msg.op = enable ? NLOP_ADD : NLOP_REMOVE;
		msg.data.proto.layer = 4;
		msg.data.proto.protocol = IPPROTO_UDP;	// UDP
		strncpy(msg.data.proto.ifname, ifp->name, sizeof(msg.data.proto.ifname));
		if (nlkernel_sendmsg(&msg) != 0)
			break;

		ok = 1;
	} while (0);

	if (ok == 0)
		return -1;

	udp_enabled[n] = enable;
	return 0;
}
int vtyhlp_enable_tcp(const char *ifname, int enable)
{
	struct interface *ifp = if_lookup_by_name(ifname);
	if (ifp == NULL)
		return -1;

	int n = ifp->ifindex;
	if (n == -1 || n >= MAX_ETH_COUNT)
		return -1;

	static int tcp_enabled[MAX_ETH_COUNT] = { 0 };
	if (enable == 1 && tcp_enabled[n] == 1)
		return 0;
	if (enable == 0 && tcp_enabled[n] == 0)
		return 0;

	int ok = 0;
	do
	{
		struct nl_kernel_msg msg;
		msg.type = NLCMD_PROTO;
		msg.op = enable ? NLOP_ADD : NLOP_REMOVE;
		msg.data.proto.layer = 4;
		msg.data.proto.protocol = IPPROTO_TCP;	// TCP
		strncpy(msg.data.proto.ifname, ifp->name, sizeof(msg.data.proto.ifname));
		if (nlkernel_sendmsg(&msg) != 0)
			break;

		ok = 1;
	} while (0);

	if (ok == 0)
		return -1;

	tcp_enabled[n] = enable;
	return 0;
}
void vtyhlp_sync_kernel_capture(struct interface *ifp)
{
	int hastcp = gapconfig_route_hastrans_tcp(ifp);
	int hasudp = gapconfig_route_hastrans_udp(ifp);

	if (hastcp == 1 || hasudp == 1)
		vtyhlp_enable_arpicmp(ifp->name, 1);

	if (hastcp == 0 && hasudp == 0)
		vtyhlp_enable_arpicmp(ifp->name, 0);

	vtyhlp_enable_tcp(ifp->name, hastcp);
	vtyhlp_enable_udp(ifp->name, hasudp);
}

int vty_onroute_doadd_mapped(struct gap_route *vtyroute, struct interface *ifp)
{
	struct route_item *route = NULL;

	int ok = 0, ret;
	do
	{
		if (vtyroute->dip_group->num != 1)
		{
			SCLogError("on vty_onroute_doadd_mapped, vty's dip_group->num is not 1 (%d)", vtyroute->dip_group->num);
			break;
		}

		if (strlen(vtyroute->entryip) == 0)
		{
			SCLogInfo("on vty_onroute_doadd_mapped, not found entryip");
			break;
		}

		route = gapconfig_newroute();
		if (route == NULL)
		{
			SCLogError("on vty_onroute_doadd_mapped, alloc route failed");
			break;
		}
		server_ids_fromstr(vtyroute->proto, route->svrids, countof(route->svrids));
		route->in_port = atoi(vtyroute->inport);
		route->src_ports = gapconfig_parse_range_str(vtyroute->sport);
		route->dst_ports = gapconfig_parse_range_str(vtyroute->dport);
		route->vtyroute = vtyroute;
		gapconfig_addroute(ifp, route);

		ret = vtyhlp_applyroute(route);
		if (ret != 0)
		{
			SCLogError("on vty_onroute_doadd_mapped, vtyhlp_applyroute failed");
			break;
		}

		ok = 1;
	} while (0);

	if (ok == 1)
		return 0;

	if (route != NULL)
	{
		gapconfig_removeroute(ifp, route);
		gapconfig_freeroute(route);
	}
	return -1;
}
int vty_onroute_doadd_trans(struct gap_route *vtyroute, struct interface *ifp)
{
	struct route_item *route = NULL;
	struct server *svr = NULL;

	int ok = 0;
	do
	{
		if (strlen(vtyroute->entryip) == 0)
		{
			SCLogInfo("on vty_onroute_doadd_trans, not found entryip");
			break;
		}

		route = gapconfig_newroute();
		if (route == NULL)
		{
			SCLogError("on vty_onroute_doadd_trans, alloc config failed");
			break;
		}
		server_ids_fromstr(vtyroute->proto, route->svrids, countof(route->svrids));
		route->in_port = atoi(vtyroute->inport);
		route->src_ports = gapconfig_parse_range_str(vtyroute->sport);
		route->dst_ports = gapconfig_parse_range_str(vtyroute->dport);
		route->vtyroute = vtyroute;
		gapconfig_addroute(ifp, route);

		vtyhlp_sync_kernel_capture(ifp);

		ok = 1;
	} while (0);

	if (ok == 1)
		return 0;

	if (svr != NULL)
	{
		gapconfig_removeserver(route, svr);
		server_free(svr);
	}

	if (route != NULL)
	{
		gapconfig_removeroute(ifp, route);
		gapconfig_freeroute(route);
	}
	return -1;
}
int vty_onservice_onoff(int enable)
{
	if (enable == 0)
		sessionmap_closeall(NULL);
	return 0;
}


int filter_sendto_socket(struct filter_header *flthdr, const void *buff, size_t bufflen)
{
	struct app_session *session = OFFSET_OBJECT(flthdr, app_session, flthdr);
	struct app_session *parent_session = NULL;

	INCREASE_OUTPKTS(session->statistics, 1);
	INCREASE_OUTBYTES(session->statistics, bufflen);
	time(&session->livetime);

	if (session->parent_id)
	{
		parent_session = sessionmap_get(session->parent_id);
		if (parent_session)
			time(&parent_session->livetime);
	}

	int ret = sessionmgr_fdsend(session->mgr, session->fd, buff, bufflen);
	if (ret == -1)
		return -1;

	// enable flow control
	if (ret > (int)g_gapcfg->limit_sockcache && session->flowlimited == 0)
	{
		struct tlvbox *obj = tlvbox_create(0);
		if (obj != NULL)
		{
			tlv_init_from_appsession(session, obj, _FWDCMD_SOCK_WINDOW);
			tlvbox_put_uint32(obj, TLV_COMM_INTDATA, 0);
			filter_sendto_forward(&session->flthdr, obj, sizeof(obj));
			tlvbox_free(obj);
			session->flowlimited = 1;
		}
	}

	return 0;
}

int filter_sendto_forward(struct filter_header *flthdr, const void *buff, size_t bufflen)
{
	// get session ptr from hdr
	struct app_session *session = OFFSET_OBJECT(flthdr, app_session, flthdr);
	int mgrid = sessionmgr_getid(session->mgr) % MGRCNT;
	evutil_socket_t dstfd = g_pci_fd[mgrid];
	if (dstfd == 0)
		return 0;

	// obj -> buffer
	struct tlvbox *obj = (struct tlvbox*)buff; assert(bufflen = sizeof(void*));
	// 	fprintf(stderr, "dump send tlv: %p\n");
	// 	tlvbox_dump(obj, 8);

	
	int ret;
	uint32_t total = (int)tlvbox_get_size(obj) + sizeof(total);
	sessionmgr_fdsend(session->mgr, dstfd, &total, sizeof(total));
	ret = sessionmgr_fdsend_buff(session->mgr, dstfd, obj->buff);
	tlvbox_clear(obj);

	if (ret > PCI_PAUSE_SIZE)
	{
		evutil_socket_t fds[2] = { g_pci_fd[mgrid], g_sessionctl_r[mgrid] };
		sessionmgr_fdwindow_all(session->mgr, 0, fds, countof(fds));
		g_pci_pause[mgrid] = 1;
		SCLogInfo("pause pci %d", mgrid);
	}
	return 0;
}

void mainmgr_onpciwrite(size_t remainlen, void *args)
{
	struct sessionmgr *mgr = args;
	int mgrid = sessionmgr_getid(mgr) % MGRCNT;
	if (g_pci_pause[mgrid] == 0)
		return;

	if (remainlen == 0)
	{
		evutil_socket_t fds[2] = { g_pci_fd[mgrid], g_sessionctl_r[mgrid] };
		sessionmgr_fdwindow_all(mgr, -1, fds, countof(fds));
		g_pci_pause[mgrid] = 0;
		SCLogInfo("resume pci %d", mgrid);
	}
}

int filter_add_server(struct filter_header *flthdr, struct server *svr)
{
	SCLogInfo("filter_add_server is run, svr->dstip = %s, svr->dstport = %d, svr->localip = %s, svr->localport = %d", 
		svr->dstip,
		svr->dstport,
		svr->localip,
		svr->localport);
	
	int ret = -1;

	if (svr->type != SVR_TYPE_INTERNAL_NAT)
	{
		gapconfig_lock();
		gapconfig_add_datasvr(svr);
		gapconfig_unlock();
	}

	if (flthdr->private != NULL)
	{
		svr->parent_sesssionid = flthdr->sessionid;
		svr->parent_acldata = SCMalloc(sizeof(struct acl_data));
		memcpy(svr->parent_acldata, flthdr->private, sizeof(struct acl_data));
	}

	if (svr->localport == 0)
		return 0;

	if (SVRID_IS_UDP_FAMILY(svr->id))
	{
		ret = udp_start_server(svr, udp_data_onsvr);
	}
	else
	{
		ret = connmgr_addlistener(g_connmgr, svr->localip, svr->localport, mainmgr_oncliin, svr);
		if (ret != 0)
		{
			SCLogInfo("add server failed: %s:%d", svr->localip, svr->localport);
		}			
		else
		{
			SCLogInfo("add server success: %s:%d", svr->localip, svr->localport);
		}
	}

	return ret;
}

int filter_remove_server(struct filter_header *hdr, struct server *svr)
{
	int ret = 0;

	gapconfig_lock();
	gapconfig_remove_datasvr(svr);
	gapconfig_unlock();
	if (SVRID_IS_UDP_FAMILY(svr->id))
	{
		ret = udp_stop_server(svr);
	}
	else
	{
		ret = connmgr_removelistener(g_connmgr, svr->localip, svr->localport);
	}

	sessionmap_freebysvr(svr);

	return ret;
}

int filter_sendto_pcap(struct filter_header *flthdr, const void *buff, size_t bufflen)
{
	struct app_session *session = OFFSET_OBJECT(flthdr, app_session, flthdr);

	INCREASE_OUTPKTS(session->statistics, 1);
	INCREASE_OUTBYTES(session->statistics, bufflen);
	time(&session->livetime);

	return nlkernel_sendpkt(flthdr->dstif, buff, bufflen);
}

///////////////////////////////////////////////////////////////
int filter_udp_sendto(struct filter_header *hdr, const void *buff, size_t len)
{
	struct app_session *session = OFFSET_OBJECT(hdr, app_session, flthdr);
	struct sockaddr_in toaddr = { 0 };

	if (hdr->svr != NULL)
	{
		toaddr.sin_addr.s_addr = hdr->ip->saddr;
		toaddr.sin_port = htons(hdr->udp->source);
	}
	else
	{
		toaddr.sin_addr.s_addr = hdr->ip->daddr;
		toaddr.sin_port = hdr->udp->dest;
	}

	INCREASE_OUTPKTS(session->statistics, 1);
	INCREASE_OUTBYTES(session->statistics, len);
	time(&session->livetime);
	sendto(session->fd, buff, (int)len, 0, (struct sockaddr *)&toaddr, sizeof(toaddr));
	return 0;
}




/*
	detect protocol belong to which service
*/
enum SVR_ID detect_service(const void *buff, size_t len)
{
	enum SVR_ID ret = _SVR_ID_NONE;
	for (enum SVR_ID i = _SVR_ID_NONE; i < _SVR_ID_COUNT; i++)
	{
		struct packet_filter *flt = pktfilter_get(i);
		if (flt == NULL || flt->checkcb == NULL)
			continue;

		ret = flt->checkcb(buff, len);
		if (ret != _SVR_ID_NONE)
			break;
	}

	if (ret == _SVR_ID_NONE)
		ret = SVR_ID_TCP;
	return ret;
}

// rebuild session's filter
void rebuildsessionfilter(struct app_session *session, enum SVR_ID newid)
{
	session->filter->onpktcb(&session->flthdr, FLTEV_ONSOCKERROR, NULL, 0);
	session->filter = pktfilter_get(newid); assert(session->filter != NULL);
	session->filter->onpktcb(&session->flthdr, FLTEV_ONCLIIN, NULL, 0);
	if (session->state == SESSION_READY)
	{
		int isok = 1;
		session->filter->onpktcb(&session->flthdr, FLTEV_ONSVROK, &isok, sizeof(isok));
	}
}

//////////////////////////////////////////////////////////////////////////
// on socket data
void mainmgr_onsockdata(const void *buff, size_t bufflen, void *args)
{
	struct app_session *session = args;
	struct app_session *parent_session = NULL;

	// first packet, guess protocol by data
	if (session->guessok == 0 && session->filter->svrid == SVR_ID_TCP)
	{
		enum SVR_ID newid = detect_service(buff, bufflen);

		// proto not in route, close the session
		if (session->flthdr.svr != NULL)
		{
			struct route_item *route = session->flthdr.svr->route;
			if (route->in_port == 0 && newid != SVR_ID_TCP && server_ids_hasid(newid, route->svrids, countof(route->svrids)) == 0)
			{
				session->filter->onpktcb(&session->flthdr, FLTEV_ONSOCKERROR, NULL, 0);
				SCLogInfo("on guess protocol, proto not found in route, svr: %s, route: %s", server_strfromid(newid), route->vtyroute->proto);

				char *err = "proto not found in route";
				char sip[20]; addr2str(session->flthdr.ip->saddr, sip);
				write_secevent_log(sip, session->flthdr.svr->dstip, session->flthdr.username, (char*)server_strfromid(session->filter->svrid), SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, route->vtyroute->name, PRI_HIGH, 0);
				appsession_free(session);
				return;
			}
		}

		if (newid != session->filter->svrid)
			rebuildsessionfilter(session, newid);
		session->guessok = 1;
	}

	// get the filter
	struct packet_filter *filter = session->filter;
	assert(filter != NULL);

	if (bufflen == 0) 
	{
		session->state = SESSION_DISCONNECTING;
	}
	else 
	{
		INCREASE_INPKTS(session->statistics, 1);
		INCREASE_INBYTES(session->statistics, bufflen);
	}
	time(&session->livetime);

	if (session->parent_id)
	{
		parent_session = sessionmap_get(session->parent_id);
		if (parent_session)
			time(&parent_session->livetime);
	}

	// fire to parser_xxxx
	size_t sz1 = tlvbox_get_size(session->flthdr.tlv_out);

	enum FLT_RET ret = filter->onpktcb(&session->flthdr, (bufflen > 0) ? FLTEV_ONSOCKDATA : FLTEV_ONSOCKERROR, (bufflen > 0) ? buff : NULL, bufflen);
	size_t sz2 = tlvbox_get_size(session->flthdr.tlv_out);

	if (ret == FLTRET_CLOSE)
	{
		SCLogInfo("filter return FLTRET_CLOSE, flt: %s", session->filter->name);
		appsession_free(session);
	}
	else if (sz1 != sz2)
	{
		tlv_init_from_appsession(session, session->flthdr.tlv_out, FWDCMD_FORWARDDATA);
		filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));
	}
}

// fire on socket sent some data
void mainmgr_onsockwrite(size_t remainlen, void *args)
{
	struct app_session* session = args;
	if (session->flowlimited == 0)
	{
		return;
	}

	// disable flow control
	if (remainlen < g_gapcfg->limit_sockcache / 2)
	{
		session->flowlimited = 0;

		struct tlvbox *obj = tlvbox_create(0);
		tlv_init_from_appsession(session, obj, _FWDCMD_SOCK_WINDOW);
		tlvbox_put_uint32(obj, TLV_COMM_INTDATA, -1);
		filter_sendto_forward(&session->flthdr, obj, sizeof(obj));
		tlvbox_free(obj);
	}
}

//////////////////////////////////////////////////////
#define  ANYADDR		"0.0.0.0"

static unsigned long g_udp_port_pool[65536 / sizeof(unsigned long)] = { 0 };
static pthread_rwlock_t g_udp_port_rwlock;
int udp_port_range_config()
{
	int ret = 0;
	ret = pthread_rwlock_init(&g_udp_port_rwlock, NULL);
	if (ret != 0)
	{
		return -1;
	}

	return 0;
}

uint16_t udp_freeport_get()
{
	int i = 0;
	int j = 0;

	pthread_rwlock_rdlock(&g_udp_port_rwlock);
	for (i = g_gapcfg->port_udp_begin; i < g_gapcfg->port_udp_end; i++)
	{
		if (g_udp_port_pool[j] == 0)
		{
			g_udp_port_pool[j] =  i;
			break;
		}
		j++;		
	}
	pthread_rwlock_unlock(&g_udp_port_rwlock);
	
	return i >= g_gapcfg->port_udp_end ? 0 : i;
}

void udp_freeport_put(uint16_t udp_port)
{
	pthread_rwlock_wrlock(&g_udp_port_rwlock);
	__clear_bit(udp_port, g_udp_port_pool);
	pthread_rwlock_unlock(&g_udp_port_rwlock);
}


// on pci data
void mainmgr_dopcidata(struct app_session *session, struct tlvbox *appobj)
{
	struct tlvhdr *hdcmd = tlvbox_find(appobj, TLV_COMM_FWDCMD);
	uint32_t fwdcmd = tlv_get_uint32(hdcmd);

	// first packet, guess protocol by data
	if (session->guessok == 0 && session->filter->svrid == SVR_ID_TCP && fwdcmd == FWDCMD_FORWARDDATA)
	{
		struct tlvhdr *hdbuff = tlvbox_find(appobj, TLV_COMM_BUFFDATA);
		assert(hdbuff != NULL);

		enum SVR_ID newid = detect_service(tlv_get_bytes(hdbuff), tlv_get_size(hdbuff));

		// proto not in route, close the session
		if (session->flthdr.svr != NULL)
		{
			struct route_item *route = session->flthdr.svr->route;
			if (route->in_port == 0 && newid != SVR_ID_TCP && server_ids_hasid(newid, route->svrids, countof(route->svrids)) == 0)
			{
				session->filter->onpktcb(&session->flthdr, FLTEV_ONSOCKERROR, NULL, 0);
				appsession_free(session);
				return;
			}
		}

		if (newid != session->filter->svrid)
			rebuildsessionfilter(session, newid);
		session->guessok = 1;
	}

	// fire to parser_xxxx
	if (fwdcmd > _FWDCMD_INTERNAL_END)
	{
		struct tlvhdr *hdcmd = tlvbox_find(appobj, TLV_COMM_FWDCMD);
		struct tlvhdr *hdstr = tlvbox_find(appobj, TLV_COMM_STRDATA);
		struct tlvhdr *hdbuff = NULL;
		while ((hdbuff = tlvbox_findnext(appobj, TLV_COMM_BUFFDATA, hdbuff)) != NULL)
		{
			ForwardObject obj = { };
			obj.cmd = tlv_get_uint32(hdcmd);
			obj.sessionid = session->id;
			if (hdstr)
				obj.strdata = tlv_get_string(hdstr);
			if (hdbuff)
			{
				obj.has_buffdata = 1;
				obj.buffdata.data = tlv_get_bytes(hdbuff);
				obj.buffdata.len = tlv_get_size(hdbuff);
			}
			enum FLT_RET ret = session->filter->onpktcb(&session->flthdr, FLTEV_ONFWDDATA, &obj, sizeof(&obj));
			if (ret == FLTRET_CLOSE)
			{
				appsession_free(session);
				break;
			}
		}
		return;
	}

	switch (fwdcmd)
	{
		// on cli in
	case _FWDCMD_CLI_IN:
	{
		enum FLT_RET ret = session->filter->onpktcb(&session->flthdr, FLTEV_ONCLIIN, NULL, 0);
		if (ret == FLTRET_CLOSE)
		{
			appsession_free(session);
			return;
		}
		
		if (SVRID_IS_UDP_FAMILY(session->filter->svrid))
		{
			session->flthdr.localport = udp_freeport_get();
			if (session->flthdr.localport == 0)
			{
				SCLogInfo("target return udp port is used up ,flt: %s", session->filter->name);
				appsession_free(session);				
				return;
			}

			if (strncmp(session->flthdr.dstif, "none", 4))
			{
				struct interface * ifp = gapconfig_get_if_by_name(session->flthdr.dstif);
				if (ifp != NULL)
				{
					session->flthdr.localip = if_get_vip(ifp);
				}
			}

			//create udp client
			{
				if (udp_start_client(ANYADDR, session->flthdr.localport, udp_data_oncli, session) != 0)
				{
					appsession_free(session);
				}
			}
		}
	}
	break;

	// on conn svr
	case _FWDCMD_CONN_SVR:
	{
		struct tlvhdr *hdstr = tlvbox_find(appobj, TLV_COMM_STRDATA);
		assert(hdstr != NULL);

		char *ip = tlv_get_string(hdstr);
		char *port = strchr(ip, ':');
		*port = 0; port++;
		session->flthdr.ip->daddr = inet_addr(ip);
		session->flthdr.tcp->dest = htons(atoi(port));
		session->state = SESSION_CONNECTING;

		struct timeval timeout = { 5, 0 };
		connmgr_addconnect(g_connmgr, ip, atoi(port), &timeout, mainmgr_onconnok, session);
	}
	break;

	// on connect reply
	case _FWDCMD_CONN_SVR_REPLY:
	{
		struct tlvhdr *hdint = tlvbox_find(appobj, TLV_COMM_INTDATA);
		assert(hdint != NULL);
		int isok = tlv_get_uint32(hdint);

		session->state = (isok == 1) ? SESSION_READY : SESSION_NULL;
		enum FLT_RET ret = session->filter->onpktcb(&session->flthdr, FLTEV_ONSVROK, &isok, sizeof(isok));
		if (ret == FLTRET_CLOSE)
			appsession_free(session);
		else
			sessionmgr_fdwindow(session->mgr, session->fd, -1);
	}
	break;

	// on close
	case _FWDCMD_SOCK_CLOSED:
	{
		SCLogInfo("target return FLTRET_CLOSE, flt: %s", session->filter->name);
		//if (session->filter->svrid >= SVR_ID_UDP)
		//{
		//	serialize_object_free(appobj);
		//	return;
		//}
		mainmgr_onctl_close(session, NULL);
	}
	break;

	// on flow control
	case _FWDCMD_SOCK_WINDOW:
	{
		struct tlvhdr *hdint = tlvbox_find(appobj, TLV_COMM_INTDATA);
		assert(hdint != NULL);
		sessionmgr_fdwindow(session->mgr, session->fd, tlv_get_uint32(hdint));
		SCLogInfo("on window control, window: %d, ssid: %d", tlv_get_uint32(hdint), session->id);
	}
	break;
	}
}

// socket connect ok
void mainmgr_onctl_connok(struct app_session *session, struct mgr_fwd_obj *fwdobj)
{
	assert(fwdobj->cmd == SSCMD_CONNOK);

	// session freed
	if (session->state == SESSION_DISCONNECTING)
	{
		appsession_free(session);
		return;
	}

	// get the filter
	struct packet_filter *filter = session->filter; assert(filter != NULL);

	// success? failed?
	int isok = (fwdobj->fd > 0);
	session->state = (isok == 1) ? SESSION_READY : SESSION_NULL;

	// fire to parser_xxxx
	enum FLT_RET fltret = filter->onpktcb(&session->flthdr, FLTEV_ONSVROK, &isok, sizeof(isok));

	// connect ok, add to session manager
	if (isok == 1)
	{
		session->fd = fwdobj->fd;
		if (sessionmgr_fdadd(session->mgr, fwdobj->fd, mainmgr_onsockdata, mainmgr_onsockwrite, NULL, session) != 0)
		{
			isok = 0;
		}
	}

	// send to fwd
	tlv_init_from_appsession(session, session->flthdr.tlv_out, _FWDCMD_CONN_SVR_REPLY);
	tlvbox_put_uint32(session->flthdr.tlv_out, TLV_COMM_INTDATA, isok);
	filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));

	// write secaudit log
	if (isok)
	{
		char sip[20], dip[20], content[100];
		addr2str(session->flthdr.ip->saddr, sip);
		addr2str(session->flthdr.ip->daddr, dip);
		snprintf(content, sizeof(content), "%s access server %s:%d", sip, dip, ntohs(session->flthdr.tcp->dest));
		write_secaudit_log("access", sip, content, PRI_LOW, 0);
	}

	if (fltret == FLTRET_CLOSE)
		appsession_free(session);
}

// on client in
void mainmgr_onctl_cliin(struct app_session *session, struct mgr_fwd_obj *fwdobj)
{
	assert(fwdobj->cmd == SSCMD_CLIIN);
	if (handle_rule_on_cliin(fwdobj->cliinfo, session) != 0) {
		appsession_free(session);
		closesocket(fwdobj->fd);
		SCLogInfo("on cliin, rule match failed, do close, ssid: %d", session->id);
		return;
	}

	// fire to parser_xxxx
	enum FLT_RET fltret = session->filter->onpktcb(&session->flthdr, FLTEV_ONCLIIN, NULL, 0);
	if (fltret == FLTRET_CLOSE)
	{
		appsession_free(session);
		closesocket(fwdobj->fd);
		return;
	}

	// SSL channel
	if (fwdobj->svr->type == SVR_TYPE_INTERNAL_SSL)
	{
		// 添加到会话管理器
		if (sessionmgr_fdadd(session->mgr, fwdobj->fd, mainmgr_onsockdata, NULL, NULL, session) != 0)
		{
			appsession_free(session);
			closesocket(fwdobj->fd);
		}
		return;
	}

	// UDP, no need connect
	if (SVRID_IS_UDP_FAMILY(session->filter->svrid))
	{
		session->state = SESSION_READY;
		return;
	}

	// state to connecting
	session->state = SESSION_CONNECTING;

	ForwardObject *obj = NULL;
	int ret, ok = 0;
	do
	{
		// send to fwd
		tlv_init_from_appsession(session, session->flthdr.tlv_out, _FWDCMD_CLI_IN);
		if (session->parent_id)
			tlvbox_put_uint32(session->flthdr.tlv_out, TLV_COMM_PARENT_SESSIONID, session->parent_id);
		tlvbox_put_string(session->flthdr.tlv_out, TLV_COMM_STRDATA, fwdobj->cliinfo);
		ret = filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));
		if (ret != 0)
		{
			break;
		}

		// send to fwd
		char buff[100] = { 0 }, *ip, *port;
		parsestring(fwdobj->cliinfo, "dip", &ip, "dport", &port, NULL);
		snprintf(buff, sizeof(buff), "%s:%s", ip, port);
		tlv_init_from_appsession(session, session->flthdr.tlv_out, _FWDCMD_CONN_SVR);
		tlvbox_put_string(session->flthdr.tlv_out, TLV_COMM_STRDATA, buff);
		ret = filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));
		if (ret != 0)
		{
			break;
		}

		// add to session manager
		ret = sessionmgr_fdadd(session->mgr, fwdobj->fd, mainmgr_onsockdata, mainmgr_onsockwrite, NULL, session);
		if (ret != 0)
		{
			break;
		}

		sessionmgr_fdwindow(session->mgr, fwdobj->fd, 0);
		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (obj != NULL)
		{
			if (obj->strdata != NULL)
				SCFree(obj->strdata);
			SCFree(obj);
		}

		appsession_free(session);
		closesocket(fwdobj->fd);
	}
}

// close a session
void mainmgr_onctl_close(struct app_session *session, struct mgr_fwd_obj *fwdobj)
{
	if (session->invalid == 1 || session->state == SESSION_DISCONNECTING)
	{
		appsession_free(session);
		return;
	}

	enum FLT_RET ret = session->filter->onpktcb(&session->flthdr, FLTEV_ONSOCKERROR, NULL, 0);
	if (ret == FLTRET_CLOSE)
	{
		// not connect ok, delay free
		if (session->state == SESSION_CONNECTING && session->flthdr.svr == NULL)
		{
			SCLogInfo("session %d connecting, can't close", session->id);
			session->state = SESSION_DISCONNECTING;
		}
		else
		{
			appsession_free(session);
		}
	}
}

// on ctl obj
void mainmgr_onctlobj(const void *buff, size_t bufflen, void *args)
{
	struct mgr_fwd_obj *fwdobj = NULL;
	while (bufflen)
	{
		fwdobj = *((struct mgr_fwd_obj**)buff);
		bufflen -= sizeof(fwdobj);
		buff = (char*)buff + sizeof(fwdobj);

		// get session obj
		struct app_session *session = sessionmap_get(fwdobj->sessionid);
		if (session == NULL)
		{
			forwardobj_free(fwdobj);
			continue;
		}

		switch (fwdobj->cmd)
		{
		case SSCMD_CLIIN:
			mainmgr_onctl_cliin(session, fwdobj);
			break;

		case SSCMD_CONNOK:
			mainmgr_onctl_connok(session, fwdobj);
			break;

		case SSCMD_CLOSE:
			mainmgr_onctl_close(session, fwdobj);
			break;
		}

		forwardobj_free(fwdobj);
	}
}

void mainmgr_oncliin(evutil_socket_t clifd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args)
{
	struct server *svr = args;
	struct route_item *route = svr->route;
	struct sockaddr_in *paddr = (struct sockaddr_in*)cliaddr;
	struct packet_filter *flt = pktfilter_get(svr->id); assert(flt != NULL);

	// arbiter not ready
	if (g_pciready == 0)
	{
		char *err = "arbiter not ready";
		socket_syncsend(clifd, err, (int)strlen(err)); os_sleep(1);
		closesocket(clifd);
		return;
	}

	// shutdown
	if (g_gapcfg->service_enabled == 0)
	{
		char *err = "device shutdown";
		socket_syncsend(clifd, err, (int)strlen(err)); os_sleep(1);
		closesocket(clifd);
		return;
	}

	// user limit
	if (session_is_full())
	{
		char *err = "user overload";
		socket_syncsend(clifd, err, (int)strlen(err)); os_sleep(1);
		closesocket(clifd);
		return;
	}

	// get enc_card userinfo from kernel
	uint8_t climac[6] = { 0 };
	struct gap_user *user = NULL;
	if (route != NULL && svr->id != SVR_ID_SSL)
	{
		getarp(route->vtyroute->inif, inet_ntoa(paddr->sin_addr), climac);

		uint32_t uid = nlkernel_getuidbyaddr(paddr->sin_addr.s_addr, paddr->sin_port, inet_addr(svr->localip), htons(svr->localport), climac);
		user = usertable_getbyid(uid, 0);

		SCLogInfo("on cliin, getid from kernel, ret: %p, uid: %d", user, uid);
	}

	// get username, routename, sif, dif

	char *username = user ? user->name : "none";
	char *sif = route ? route->vtyroute->inif : "none";
	char *dif = route ? route->vtyroute->outif : "none";
	char *routename = route ? route->vtyroute->name : "none";
	if (svr->parent_acldata != NULL)
	{
		username = svr->parent_acldata->user;
		routename = svr->parent_acldata->route;
		sif = svr->parent_acldata->inif;
		dif = svr->parent_acldata->outif;
	}

	// route match
	int guessok = 0;
	if (route != NULL)
	{
		struct ip_range *p1 = vtyiplist_match(route->vtyroute->sip_group, ntohl(paddr->sin_addr.s_addr));
		struct ipport_range *p2 = rangelist_match(route->src_ports, ntohs(paddr->sin_port));
		if (p1 == NULL || p2 == NULL)
		{
			char *err = "cliaddr not found in route";
			socket_syncsend(clifd, err, (int)strlen(err)); os_sleep(1);
			closesocket(clifd);

			// 写日志
			char sip[20]; strcpy(sip, inet_ntoa(paddr->sin_addr));
			write_secevent_log(sip, svr->dstip, user ? user->name : "none", (char*)server_strfromid(flt->svrid), SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, route->vtyroute->name, PRI_HIGH, 0);
			return;
		}

		if (server_ids_hasid(SVR_ID_TCP, route->svrids, countof(route->svrids)) == 1 ||
			server_ids_hasid(SVR_ID_UDP, route->svrids, countof(route->svrids)) == 1)
			guessok = 1;
	}

	/* 时间校验 */
	if (route != NULL)
	{
		if (route->vtyroute->tacl.u.tr && check_time_privilege(&route->vtyroute->tacl) != 0)
		{
			SCLogInfo("check_time_privilege failed(%s,%s,%p).", route->vtyroute->effectime, route->vtyroute->tacl.u.tr->name, &route->vtyroute->tacl);
			char *err = "Access time not allowed";
			socket_syncsend(clifd, err, (int)strlen(err)); os_sleep(1);
			closesocket(clifd);
			return;
		}
	}

	// rebuild svr->dstip when dst ipgroup changed
	if (route != NULL && route->in_port != 0 && inet_addr(svr->dstip) != htonl(route->vtyroute->dip_group->ir[0].first_ip))
	{
		SCFree(svr->dstip);
		svr->dstip = SCMalloc(20);
		addr2str(htonl(route->vtyroute->dip_group->ir[0].first_ip), svr->dstip);
	}

	// get route type
	enum ROUTE_TYPE routetype;
	if (route != NULL)
		routetype = ROUTE_IS_TRANSPARENT(route->in_port) ? ROUTE_TRANSPARENT : ROUTE_MAPPED;
	else
		routetype = ROUTE_IS_TRANSPARENT(svr->localport) ? ROUTE_TRANSPARENT : ROUTE_MAPPED;

	// generic session id
	uint32_t sessionid = appsession_genericid();
	if (svr->parent_sesssionid > 0)
	{
		while ((sessionid % MGRCNT) != (svr->parent_sesssionid % MGRCNT))
			sessionid = appsession_genericid();
	}
	struct sessionmgr *mgr = g_sessionmgr[sessionid % MGRCNT];

	// get local address
	struct sockaddr_in localaddr = { 0 };
	socklen_t localaddrlen = sizeof(localaddr);
	getsockname(clifd, (struct sockaddr*)&localaddr, &localaddrlen);

	// create the app session
	struct app_session *session = NULL;
	struct mgr_fwd_obj *fwdobj = NULL;
	int ret, putok = 0, ok = 0;
	do
	{
		session = appsession_pool_get();
		if (session == NULL)
			break;
		session->mgr = mgr;
		session->fd = clifd;
		session->id = sessionid;
		session->parent_id = svr->parent_sesssionid;
		session->filter = flt;
		session->guessok = guessok;
		session->flthdr.tlv_out = tlvbox_create(0);
		session->flthdr.routetype = routetype;
		session->flthdr.username = SCStrdup(username);
		session->flthdr.svr = svr;
		session->flthdr.sessionid = session->id;
		session->flthdr.timeout = g_gapcfg->timeout_session;
		session->flthdr.ip = &session->flthdr._ip;
		session->flthdr.tcp = &session->flthdr._tcp;
		session->flthdr.ip->saddr = paddr->sin_addr.s_addr;
		session->flthdr.tcp->source = paddr->sin_port;
		session->flthdr.ip->daddr = (svr->dstip ? inet_addr(svr->dstip) : 0);
		session->flthdr.tcp->dest = (svr->dstip ? htons(svr->dstport) : 0);
		session->flthdr.localip = localaddr.sin_addr.s_addr;
		session->flthdr.localport = localaddr.sin_port;
		session->flthdr.svr_add_cb = filter_add_server;
		session->flthdr.svr_remove_cb = filter_remove_server;
		session->flthdr.reqcb = filter_sendto_socket;
		session->flthdr.respcb = filter_sendto_socket;
		session->flthdr.fwdcb = filter_sendto_forward;
		time(&session->starttime);
		time(&session->livetime);
		strncpy(session->flthdr.srcif, sif, sizeof(session->flthdr.srcif));
		strncpy(session->flthdr.dstif, dif, sizeof(session->flthdr.dstif));
		strncpy(session->flthdr.routename, routename, sizeof(session->flthdr.routename));

		ret = sessionmap_put(session);
		if (ret != 0)
			break;
		putok = 1;

		char info[3000];
		snprintf(info, sizeof(info), "dir=%d;smac=%02X:%02X:%02X:%02X:%02X:%02X;sip=%s;sport=%d;dip=%s;dport=%d;uname=%s;sif=%s;dif=%s;routename=%s;routetype=%d;guessok=%d;srclevel=%d;dstlevel=%d",
			(RUN_AS_OUTER() ? 1 : 2), climac[0], climac[1], climac[2], climac[3], climac[4], climac[5],
			inet_ntoa(paddr->sin_addr), ntohs(paddr->sin_port), (svr ? svr->dstip : "0.0.0.0"), (svr ? svr->dstport : 0),
			session->flthdr.username, sif, dif, routename,
			session->flthdr.routetype, session->guessok, (route ? route->vtyroute->sip_group->level : 0), (route ? route->vtyroute->dip_group->level : 0));

		// get fwd socket
		evutil_socket_t forwardsock = g_sessionctl[sessionmgr_getid(session->mgr)];

		// create fwdobj, send to business thread（mainmgr_onctl_cliin）
		fwdobj = SCMalloc(sizeof(struct mgr_fwd_obj));
		if (fwdobj == NULL)
			break;
		memset(fwdobj, 0, sizeof(*fwdobj));
		fwdobj->cmd = SSCMD_CLIIN;
		fwdobj->sessionid = session->id;
		fwdobj->fd = clifd;
		fwdobj->svr = svr;
		fwdobj->cliinfo = SCStrdup(info);
		if (fwdobj->cliinfo == NULL)
			break;

		ret = socket_syncsend(forwardsock, &fwdobj, sizeof(fwdobj));
		if (ret == -1)
			break;

		time(&svr->livetime);
		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (session != NULL)
		{
			if (fwdobj != NULL)
				forwardobj_free(fwdobj);

			if (putok == 1)
				sessionmap_remove(session);

			session->fd = 0;
			appsession_free(session);
		}

		char *err = "no memory";
		socket_syncsend(clifd, err, (int)strlen(err)); os_sleep(1);
		closesocket(clifd);
	}
}

// connect ok/failed
void mainmgr_onconnok(evutil_socket_t clifd, void *args)
{
	struct app_session *session = args;
	session->state = SESSION_NULL;

	if (clifd == -1)
	{
		char ip[20];
		addr2str(session->flthdr.ip->daddr, ip);
		SCLogInfo("mainmgr_onconnok, connect %s:%d failed", ip, ntohs(session->flthdr.tcp->dest));
	}

	// get local address
	struct sockaddr_in localaddr = { 0 };
	socklen_t localaddrlen = sizeof(localaddr);
	getsockname(clifd, (struct sockaddr*)&localaddr, &localaddrlen);
	session->flthdr.localip = localaddr.sin_addr.s_addr;
	session->flthdr.localport = localaddr.sin_port;

	// get forward socket
	evutil_socket_t forwardsock = g_sessionctl[sessionmgr_getid(session->mgr)];

	// create fwdobj, send to business thread（mainmgr_onctl_connok）
	struct mgr_fwd_obj *fwdobj = SCMalloc(sizeof(struct mgr_fwd_obj));
	if (fwdobj == NULL)
	{
		appsession_free(session);
		return;
	}
	memset(fwdobj, 0, sizeof(*fwdobj));
	fwdobj->cmd = SSCMD_CONNOK;
	fwdobj->sessionid = session->id;
	fwdobj->fd = clifd;
	int ret = socket_syncsend(forwardsock, &fwdobj, sizeof(fwdobj));
	if (ret == -1)
		SCFree(fwdobj);
}

struct app_session* appsession_create_from_tlv(struct tlvbox *obj)
{
	struct app_session *session = NULL;
	struct app_session *parent_session = NULL;
	char *strdata = NULL;

	do
	{
		struct tlvhdr *hdfwdcmd = tlvbox_find(obj, TLV_COMM_FWDCMD);
		uint32_t fwdcmd = tlv_get_uint32(hdfwdcmd);
		if (fwdcmd != _FWDCMD_CLI_IN)
			break;

		struct tlvhdr *hdsvrid = tlvbox_find(obj, TLV_COMM_SERVERID);
		struct tlvhdr *hdstrdata = tlvbox_find(obj, TLV_COMM_STRDATA);
		struct tlvhdr *hdsessionid = tlvbox_find(obj, TLV_COMM_SESSIONID);
		struct tlvhdr *hdparentsessionid = tlvbox_find(obj, TLV_COMM_PARENT_SESSIONID);
		assert(hdsvrid != NULL);
		assert(hdstrdata != NULL);
		assert(hdsessionid != NULL);

		uint32_t svrid = tlv_get_uint32(hdsvrid);
		uint32_t sessionid = tlv_get_uint32(hdsessionid);
		strdata = SCStrdup(tlv_get_string(hdstrdata));

		// get ip, port
		SCLogInfo("connect info: %s\n", strdata);

		char *cliip, *cliport, *dstip, *dstport, *username, *srcif, *dstif, *routename, *routetype, *guessok;
		parsestring(strdata, "sip", &cliip, "sport", &cliport, "dip", &dstip, "dport", &dstport, "uname", &username,
			"sif", &srcif, "dif", &dstif, "routename", &routename, "routetype", &routetype, "guessok", &guessok, NULL);
		if (cliip == NULL || cliport == NULL || dstip == NULL || dstport == NULL || username == NULL || dstif == NULL || routename == NULL || routetype == NULL || guessok == NULL)
			break;

		// create app session
		session = appsession_pool_get();
		if (session == NULL)
			break;
		session->id = sessionid;
		session->parent_id = (hdparentsessionid ? tlv_get_uint32(hdparentsessionid) : 0);
		session->filter = pktfilter_get(svrid);
		session->guessok = atoi(guessok);
		session->flthdr.tlv_out = tlvbox_create(0);
		session->flthdr.username = username ? SCStrdup(username) : "none";
		session->flthdr.routetype = atoi(routetype);
		session->flthdr.sessionid = sessionid;
		session->flthdr.timeout = g_gapcfg->timeout_session;
		strncpy(session->flthdr.srcif, srcif, sizeof(session->flthdr.srcif));
		strncpy(session->flthdr.dstif, dstif, sizeof(session->flthdr.dstif));
		strncpy(session->flthdr.routename, routename, sizeof(session->flthdr.routename));
		session->flthdr.ip = &session->flthdr._ip;
		session->flthdr.ip->saddr = inet_addr(cliip);
		session->flthdr.ip->daddr = inet_addr(dstip);
		time(&session->starttime);
		time(&session->livetime);
		if (SVRID_IS_UDP_FAMILY(svrid))
		{
			session->mgr = g_sessionmgr[0];
			session->flthdr.udp = &session->flthdr._udp;
			session->flthdr.udp->source = htons(atoi(cliport));
			session->flthdr.udp->dest = htons(atoi(dstport));
			session->flthdr.svr_add_cb = filter_add_server;
			session->flthdr.svr_remove_cb = filter_remove_server;
			session->flthdr.reqcb = filter_udp_sendto;
			session->flthdr.respcb = filter_udp_sendto;
			session->flthdr.fwdcb = filter_sendto_forward;
		}
		else
		{
			session->mgr = g_sessionmgr[sessionid % MGRCNT];
			session->flthdr.tcp = &session->flthdr._tcp;
			session->flthdr.tcp->source = htons(atoi(cliport));
			session->flthdr.tcp->dest = htons(atoi(dstport));
			session->flthdr.svr_add_cb = filter_add_server;
			session->flthdr.svr_remove_cb = filter_remove_server;
			session->flthdr.reqcb = filter_sendto_socket;
			session->flthdr.respcb = filter_sendto_socket;
			session->flthdr.fwdcb = filter_sendto_forward;
		}

		if (sessionmap_put(session) != 0)
			break;

		return session;
	} while (0);

	if (strdata)
		SCFree(strdata);

	if (session != NULL)
	{
		sessionmap_remove(session);
		if (session->filter->svrid > SVR_ID_UDP)
			appsession_free(session);
	}
	return NULL;
}
void mainmgr_onpcidata(const void *buff, size_t len, void *args)
{
	struct sessionmgr *mgr = args;

	if (buff == NULL)
	{
		int id = sessionmgr_getid(mgr);
		int ret = sessionmgr_fdclose(mgr, g_pci_fd[id]);
		evbuffer_free(g_pci_buff[id]);
		g_pci_buff[id] = NULL;
		g_pci_fd[id] = 0;
		SCLogInfo("pci channel %d closed, ret: %d", id, ret);

		if (RUN_AS_OUTER())
			g_pciready = 0;
		
		struct sessionmgr* pSessionmgr = sessionmgr_current();
		sessionmap_closeall(pSessionmgr);		
		
		return;
	}

	struct evbuffer *pcibf = g_pci_buff[sessionmgr_getid(mgr)];
	evbuffer_add(pcibf, buff, len);
	while (1)
	{
		// check buffer's length
		uint32_t total = 0;
		if (evbuffer_copyout(pcibf, &total, sizeof(total)) != sizeof(total))
			return;
		if (evbuffer_get_length(pcibf) < total)
			return;

		// tlv block
		uint8_t *data = evbuffer_pullup(pcibf, total);
		struct tlvbox *tlv = tlvbox_attach(data + 4, total - 4);

		// sessionid
		struct tlvhdr *hdsessionid = tlvbox_find(tlv, TLV_COMM_SESSIONID);
		uint32_t sessionid = tlv_get_uint32(hdsessionid);

		struct app_session *session = sessionmap_get(sessionid);
		if (session == NULL) {
			session = appsession_create_from_tlv(tlv);
			if (session&&handle_rule_on_tvldata(tlv, session) != 0) {
				SCLogInfo("on pcidata, rule match failed, do close, sessionid=%u.", session->id);
				sessionmap_postclose(session);
				session = NULL;
			}
		}

		// 		fprintf(stderr, "dump recv tlv: %p\n");
		// 		tlvbox_dump(tlv, 8);

		if (session != NULL)
		{
			session->flthdr.tlv_in = tlv;
			mainmgr_dopcidata(session, tlv);
		}

		tlvbox_free(tlv);
		evbuffer_drain(pcibf, total);
	}
}

// on kernel's capture data
void mainmgr_oncapdata(const void *buff, size_t bufflen, void *args)
{
	size_t sz1, sz2;
	struct app_session *session = args;
	struct nl_kerne_report_msg *msg = NULL;

	while (bufflen)
	{
		msg = *((struct nl_kerne_report_msg**)buff);
		bufflen -= sizeof(msg);
		buff = (char*)buff + sizeof(msg);

		if (g_gapcfg->service_enabled == 0)
		{
			SCFree(msg);
			continue;
		}

		sz1 = tlvbox_get_size(session->flthdr.tlv_out);
		session->filter->onpktcb(&session->flthdr, FLTEV_ONSOCKDATA, msg, sizeof(msg));
		sz2 = tlvbox_get_size(session->flthdr.tlv_out);
		if (sz1 != sz2)
		{
			tlv_init_from_appsession(session, session->flthdr.tlv_out, FWDCMD_FORWARDDATA);
			filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));
		}

		SCFree(msg);
	}
}
void udp_data_oncli(const void *buff, size_t len, evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args)
{

	struct app_session *session = args;
	//session->filter->onpktcb(&session->flthdr, FLTEV_ONSOCKDATA, buff, len);

	size_t sz1 = tlvbox_get_size(session->flthdr.tlv_out);
	enum FLT_RET ret = session->filter->onpktcb(&session->flthdr, (len > 0) ? FLTEV_ONSOCKDATA : FLTEV_ONSOCKERROR, (len > 0) ? buff : NULL, len);
	size_t sz2 = tlvbox_get_size(session->flthdr.tlv_out);

	if (ret == FLTRET_CLOSE)
	{
		SCLogInfo("filter return FLTRET_CLOSE, flt: %s", session->filter->name);
		appsession_free(session);
	}
	else if (sz1 != sz2)
	{
		tlv_init_from_appsession(session, session->flthdr.tlv_out, FWDCMD_FORWARDDATA);
		filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));
	}

}

void udp_data_onsvr(const void *buff, size_t len, evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args)
{
	struct server* p_svr = args;
	struct sockaddr_in* p_cliaddr = (struct sockaddr_in *)cliaddr;
	struct route_item * p_route = p_svr->route;

	struct packet_filter* filter = pktfilter_get(p_svr->id);
	int isnew = 0;
	struct app_session *session, tmp;

	tmp.flthdr.ip = &tmp.flthdr._ip;
	tmp.flthdr.udp = &tmp.flthdr._udp;
	tmp.flthdr.ip->saddr = p_cliaddr->sin_addr.s_addr;
	tmp.flthdr.ip->daddr = inet_addr(p_svr->dstip);
	tmp.flthdr.udp->source = ntohs(p_cliaddr->sin_port);
	tmp.flthdr.udp->dest = p_svr->dstport;

	//session = sessionmap_lookup(&tmp);
	session = sessionmap_get(fd);
	if (session == NULL)
	{
		if (p_route != NULL && p_cliaddr != NULL && p_svr->type != SVR_TYPE_INTERNAL_DATA)
		{
			struct ip_range *p1 = vtyiplist_match(p_route->vtyroute->sip_group, ntohl(p_cliaddr->sin_addr.s_addr));
			struct ipport_range *p2 = rangelist_match(p_route->src_ports, ntohs(p_cliaddr->sin_port));
			if (p1 == NULL || p2 == NULL)
			{
				return;
			}
		}

		// get route type
		enum ROUTE_TYPE routetype;
		if (p_route != NULL)
			routetype = (p_route->in_port > 0) ? ROUTE_MAPPED : ROUTE_TRANSPARENT;
		else
			routetype = (p_svr->localport > 0) ? ROUTE_MAPPED : ROUTE_TRANSPARENT;


		session = appsession_pool_get();
		session->fd = fd;
		session->fd_is_udp_svr = 1;
		session->flthdr.routetype = routetype;
		session->flthdr.tlv_out = tlvbox_create(0);
		session->id = fd;//appsession_genericid();
		session->mgr = g_sessionmgr[0];
		session->filter = filter;
		session->flthdr.sessionid = session->id;
		session->flthdr.timeout = g_gapcfg->timeout_session;
		session->flthdr.svr = p_svr;
		session->filter->svrid = p_svr->id;
		session->flthdr.reqcb = filter_udp_sendto;
		session->flthdr.respcb = filter_udp_sendto;
		session->flthdr.fwdcb = filter_sendto_forward;
		session->flthdr.svr_add_cb = filter_add_server;
		session->flthdr.svr_remove_cb = filter_remove_server;

		session->flthdr.ip = &session->flthdr._ip;
		session->flthdr.ip->saddr = p_cliaddr->sin_addr.s_addr;
		session->flthdr.ip->daddr = inet_addr(p_svr->dstip);

		session->flthdr.udp = &session->flthdr._udp;
		session->flthdr.udp->source = ntohs(p_cliaddr->sin_port);
		session->flthdr.udp->dest = p_svr->dstport;
		session->flthdr.localip = inet_addr(p_svr->localip);
		session->flthdr.localport = p_svr->localport;

		if (p_route == NULL)
		{
			strncpy(session->flthdr.srcif, "none", sizeof(session->flthdr.srcif));
			strncpy(session->flthdr.dstif, "none", sizeof(session->flthdr.dstif));
			strncpy(session->flthdr.routename, "none", sizeof(session->flthdr.routename));
		}
		else
		{
			strncpy(session->flthdr.srcif, p_route->vtyroute->inif, sizeof(session->flthdr.srcif));
			strncpy(session->flthdr.dstif, p_route->vtyroute->outif, sizeof(session->flthdr.dstif));
			strncpy(session->flthdr.routename, p_route->vtyroute->name, sizeof(session->flthdr.routename));
		}
		time(&session->starttime);
		time(&session->livetime);

		sessionmap_put(session);
		isnew = 1;
	}

	if (isnew)
	{
		if (filter->onpktcb(&session->flthdr, FLTEV_ONCLIIN, NULL, 0) != FLTRET_OK)
		{
			sessionmap_remove(session);
			appsession_free(session);
			return;
		}

		uint8_t climac[6] = { 0 };
		getarp(session->flthdr.srcif, inet_ntoa(p_cliaddr->sin_addr), climac);
		char info[3000];
		snprintf(info, sizeof(info), "dir=%d;smac=%02X:%02X:%02X:%02X:%02X:%02X;sip=%s;sport=%d;dip=%s;dport=%d;uid=%d;uname=%s;sif=%s;dif=%s;routename=%s;routetype=%d;guessok=%d;srclevel=%d;dstlevel=%d",
			(RUN_AS_OUTER() ? 1 : 2), climac[0], climac[1], climac[2], climac[3], climac[4], climac[5],
			inet_ntoa(p_cliaddr->sin_addr), ntohs(p_cliaddr->sin_port), (p_svr->dstip ? p_svr->dstip : "0.0.0.0"), (p_svr->dstip ? p_svr->dstport : 0),
			0, "none", (p_route ? p_route->vtyroute->inif : "none"), (p_route ? p_route->vtyroute->outif : "none"), (p_route ? p_route->vtyroute->name : "none"), session->flthdr.routetype,
			session->flthdr.routetype, session->guessok, (p_route ? p_route->vtyroute->sip_group->level : 0), (p_route ? p_route->vtyroute->dip_group->level : 0));
		SCLogInfo("info:\n %s\n", info);

		/* 时间校验 */
		if (p_route != NULL)
		{
			if (p_route->vtyroute->tacl.u.tr && check_time_privilege(&p_route->vtyroute->tacl) != 0)
			{
				SCLogInfo("check_time_privilege failed(%s,%s,%p),Access time not allowed.", p_route->vtyroute->effectime, p_route->vtyroute->tacl.u.tr->name, &p_route->vtyroute->tacl);
				appsession_free(session);
				return;
			}
		}

		if (handle_rule_on_cliin(info, session) != 0)
		{
			appsession_free(session);
			return;
		}

		tlv_init_from_appsession(session, session->flthdr.tlv_out, _FWDCMD_CLI_IN);
		tlvbox_put_string(session->flthdr.tlv_out, TLV_COMM_STRDATA, info);
		filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));
	}

	time(&p_svr->livetime);
	INCREASE_INPKTS(session->statistics, 1);
	INCREASE_INBYTES(session->statistics, len);
	time(&session->livetime);

	size_t sz1 = tlvbox_get_size(session->flthdr.tlv_out);
	enum FLT_RET ret = filter->onpktcb(&session->flthdr, (len > 0) ? FLTEV_ONSOCKDATA : FLTEV_ONSOCKERROR, (len > 0) ? buff : NULL, len);
	size_t sz2 = tlvbox_get_size(session->flthdr.tlv_out);

	if (ret == FLTRET_CLOSE)
	{
		SCLogInfo("filter return FLTRET_CLOSE, flt: %s", session->filter->name);
		appsession_free(session);
	}
	else if (sz1 != sz2)
	{
		tlv_init_from_appsession(session, session->flthdr.tlv_out, FWDCMD_FORWARDDATA);
		filter_sendto_forward(&session->flthdr, session->flthdr.tlv_out, sizeof(session->flthdr.tlv_out));
	}

	return;
}

int udp_start_server(struct server *svr, ONUDPDATA_CB cb)
{
	evutil_socket_t fd = new_udp_service(svr->localip, svr->localport, NULL);
	if (fd == -1)
		return -1;
	sessionmgr_udpfdadd(g_sessionmgr[0], fd, cb, NULL, NULL, svr);
	svr->udp_svr_fd = fd;
	return 0;
}

int udp_start_client(const char *localaddr, uint16_t localport, ONUDPDATA_CB cb, void *args)
{
	int ret, ok = 0;
	do
	{
		evutil_socket_t fd = new_udp_service(localaddr, localport, NULL);
		if (fd == -1)
			break;

		struct app_session *session = (struct app_session *)args;
		session->fd = fd;
		ret = sessionmgr_udpfdadd(g_sessionmgr[0], fd, cb, NULL, NULL, session);
		if (ret != 0)
		{
			break;

		}

		ok = 1;
	} while (0);
	if (ok != 1)
		return -1;
	return 0;

}

int udp_stop_server(struct server *svr)
{
	sessionmap_freebysvr(svr);
	sessionmgr_fdclose(g_sessionmgr[0], svr->udp_svr_fd);
	del_ipt_allowed_port(PORT_TYPE_UDP, svr->localport);
	return 0;
}

int gap20_ontimer(struct thread *t)
{
	thread_add_timer(master, gap20_ontimer, NULL, 1);

	// connect arbiter
	if (g_pciready == 0 && pcidrv_init() == 0)
	{
		g_pciready = 1;
		SCLogInfo("arbiter ready");
	}

	// check session timeout
	session_checktimeout();

	// check natserver timeout
	static int nattimer = 0;
	nattimer++;
	if (nattimer > 60)
	{
		nattimer = 0;
		natserver_checktimeout();
	}


	// test code
	struct stat st;
	if (stat("/etc/gapdump", &st) == 0)
	{
		unlink("/etc/gapdump");
		gapconfig_dump();
	}
	return 0;
}


int inner_outer_run()
{
	int ret;

	// reset kernel and nat
	ret = nlkernel_clearconfig();
	os_exec("iptables -t nat -F");

	// init gapcinfig
	ret = gapconfig_init();
	if (ret != 0)
	{
		SCLogError("gapconfig_init: %d", ret);
		goto FREE;
	}
	config_init(SYSCONFDIR "inouter.conf");
	g_gapcfg->ssl_svrcacrt = SCStrdup(GETSCFG("ssl_svrcacrt", "/etc/openssl/private/ca.crt"));
	g_gapcfg->ssl_svrcrt = SCStrdup(GETSCFG("ssl_svrcrt", "/etc/openssl/certs/gap.crt"));
	g_gapcfg->ssl_svrkey = SCStrdup(GETSCFG("ssl_svrkey", "/etc/openssl/private/gap.key"));
	g_gapcfg->port_ftp_begin = GETICFG("port_ftp_begin", 60000);
	g_gapcfg->port_ftp_end = GETICFG("port_ftp_end", 65000);
	g_gapcfg->port_udp_begin = GETICFG("port_udp_begin", 35000);
	g_gapcfg->port_udp_end = GETICFG("port_udp_end", 40000);
	g_gapcfg->port_rtsp_begin = GETICFG("port_rtsp_begin", 40000); //udp port
	g_gapcfg->port_rtsp_end = GETICFG("port_rtsp_end", 45000); //udp port
	g_gapcfg->port_nat_begin = GETICFG("port_nat_begin", 40000);
	g_gapcfg->port_nat_end = GETICFG("port_nat_end", 60000);
	g_gapcfg->port_opc_begin = GETICFG("port_opc_begin", 30000);
	g_gapcfg->port_opc_end = GETICFG("port_opc_end", 30999);
	g_gapcfg->port_sip_begin = GETICFG("port_sip_begin", 31000);
	g_gapcfg->port_sip_end = GETICFG("port_sip_end", 31999);
	g_gapcfg->limit_sockcache = GETICFG("limit_sockcache", 1 * 1024 * 1024);
	g_gapcfg->limit_usercount = GETICFG("limit_usercount", 100000);
	g_gapcfg->timeout_session = GETICFG("timeout_session", 5 * 60);
	g_gapcfg->ssh_login_permission = GETICFG("ssh_login_permission", 1);
	g_gapcfg->console_login_permission = GETICFG("console_login_permission", 1);
	config_free();

	vrf_init();
	zebra_init(master);

	ret = udp_port_range_config();
	if (ret != 0)
	{
		SCLogError("udp_port_range_config: %d", ret);
		goto FREE;
	}

	ret = filter_init();
	if (ret != 0)
	{
		SCLogError("filter_init: %d", ret);
		goto FREE;
	}

	ret = sessionmap_init();
	if (ret != 0)
	{
		SCLogError("ssmap_init: %d", ret);
		goto FREE;
	}

	ret = mgr_init();
	if (ret != 0)
	{
		SCLogError("mgr_init: %d", ret);
		goto FREE;
	}

#ifdef GAP_ENABLE_GUANGTIE_FEATURE
	ret = svrs_init();
	if (ret != 0)
	{
		SCLogError("svrs_init: %d", ret);
		goto FREE;
	}
#endif	

	ret = gap_dbsync_init();
	if (ret != 0)
	{
		SCLogError("gap_dbsync_init: %d", ret);
	}
	ret = pcidrv_init();
	if (ret == 0)
	{
		g_pciready = 1;
		SCLogInfo("arbiter ready");
	}
	else
	{
		SCLogInfo("arbiter not ready, delay connect...");
	}

	ret = kernel_init();
	if (ret != 0)
	{
		SCLogError("capture_init: %d", ret);
		goto FREE;
	}

	ret = ipt_init(128);
	if (ret != 0)
	{
		SCLogError("ipt_init: %d", ret);
		goto FREE;
	}

	ret = ipt_log_init();
	if (ret != 0)
	{
		SCLogError("ipt_log_init: %d", ret);
		goto FREE;
	}

	ret = file_sync_init();
	if (ret != 0)
	{
		SCLogError("file_sync_init: %d", ret);
		goto FREE;
	}

	ret = db_mysql_init(master);
	if (ret != 0)
	{
		SCLogError("db_mysql_init: %d", ret);
		//goto FREE;
	}
	/* 更新session的状态 */
	update_session_state();

	est_ontimer_start(master);
	thread_add_timer(master, gap20_ontimer, NULL, 1);

	return ret;

FREE:
	exit(-1);
}

int main_outer()
{
	return inner_outer_run();
}

int main_inner()
{
	return inner_outer_run();
}
