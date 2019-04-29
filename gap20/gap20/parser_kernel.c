
#include "app_common.h"
#include "parser_kernel.h"
#include "parser_tcp.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "nlkernelmsg.h"
#include "usertable.h"
#include "gapconfig.h"
#include "sockmgr.h"

struct kernel_ip_cache
{
	uint32_t ip;
	uint8_t mac[6];
	char ifname[16];
	time_t livetime; // TODO: 加上老化机制，定时清空超时条目
};
struct kernel_session
{
	HashListTable *arptable;    // TODO: 定时清空这个表
	struct array *port2item;
	struct list_head freeports;
	struct list_head usedports;
};

uint32_t kernel_hashlist_ipcache_hash(HashListTable *tb, void *ptr, uint16_t sz)
{
	struct kernel_ip_cache *session = ptr;
	return session->ip % tb->array_size;
}

char kernel_hashlist_ipcache_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct kernel_ip_cache *session1 = p1;
	struct kernel_ip_cache *session2 = p2;
	return session1->ip == session2->ip;
}

void kernel_hashlist_ipcache_onfree(void *ptr)
{
}

struct kernel_ip_cache* kernel_ip_cache_find(HashListTable *table, uint32_t addr, int addifnotexist)
{
	struct kernel_ip_cache *item, tmp; tmp.ip = addr;
	item = HashListTableLookup(table, &tmp, sizeof(&tmp));
	if (item == NULL && addifnotexist == 1)
	{
		item = SCMalloc(sizeof(struct kernel_ip_cache));
		if (item == NULL)
			return NULL;

		item->ip = addr;
		if (HashListTableAdd(table, item, sizeof(item)) != 0)
		{
			SCFree(item);
			return NULL;
		}
	}
	return item;
}

struct port_item
{
	struct list_head _entry;
	uint16_t port;
};

void natport_put(struct kernel_session *session, uint16_t port)
{
	SCLogInfo("put port to freelist, port: %d", port);

	port = port - g_gapcfg->port_nat_begin;

	struct port_item *item = array_getat(session->port2item, port);

	assert(item->port == port);

	list_del(&item->_entry);
	list_add_tail(&item->_entry, &session->freeports);
}

void natport_onsvrfree(struct server *svr, void *args)
{
	struct kernel_session *session = args;
	natport_put(session, svr->localport);
}

struct list_head* list_remove_head(struct list_head *list)
{
	struct list_head *ret = list->next;
	list_del(list->next);
	return ret;
}

uint16_t natport_get(struct kernel_session *session, const char *ip, int type)
{
	uint16_t ret = 0;

	while (list_empty(&session->freeports) == 0)
	{
		struct list_head *tmp = list_remove_head(&session->freeports);
		struct port_item *item = list_entry(tmp, struct port_item, _entry);

		list_add_tail(&item->_entry, &session->usedports);

		if (tcpudp_port_test(ip, item->port, type) == 0)
		{
			ret = item->port + g_gapcfg->port_nat_begin;
			break;
		}
	}

	SCLogInfo("get port from freelist, ret: %d", ret);
	return ret;
}

enum FLT_RET kernel_oncappkt(struct filter_header *hdr, struct nl_kerne_report_msg *msg)
{
	struct kernel_session *session = hdr->user;

	struct ethhdr *eth = (struct ethhdr*)msg->data;
	struct _arphdr *arp = (struct _arphdr*)((char*)eth + sizeof(*eth));
	struct iphdr *ip = (struct iphdr*)((char*)eth + sizeof(*eth));

	char dstif[20] = { 0 };
	char *proto = "";
	uint32_t isreq = 0, srcip = 0, dstip = 0;

	// ARP
	if (ntohs(eth->h_proto) == 0x0806)
	{
		if (ntohs(arp->ar_op) != 1 && ntohs(arp->ar_op) != 2)   // 1: req   2: resp
			return FLTRET_OK;
		if (arp->ar_hln != 6 || arp->ar_pln != 4)
			return FLTRET_OK;

		srcip = *((uint32_t*)arp->ar_sip);
		dstip = *((uint32_t*)arp->ar_tip);
		isreq = (ntohs(arp->ar_op) == 1);
		proto = "arp";

		if (isreq == 1)    // req
		{
			// 路由是否允许通行
			struct route_item *route = gapconfig_findroute(msg->ifname, 0, 0, NULL, ntohl(dstip), 0);
			if (route == NULL)
			{
				// 没有匹配路由，但需要支持反向ARP请求，所以判断请求目标是否曾发送过ARP请求，发过则允许该ARP通行
				struct kernel_ip_cache *dstitem = kernel_ip_cache_find(session->arptable, dstip, 0);
				if (dstitem == NULL)
					return FLTRET_OK;
				strncpy(dstif, dstitem->ifname, sizeof(dstif));
			}

			// 保存请求方IF、MAC等信息
			struct kernel_ip_cache *item = kernel_ip_cache_find(session->arptable, srcip, 1);
			if (item == NULL)
				return FLTRET_OK;
			memcpy(item->mac, arp->ar_sha, 6);
			strncpy(item->ifname, msg->ifname, sizeof(item->ifname));

			// 目标IF
			if (route != NULL)
				strncpy(dstif, route->vtyroute->outif, sizeof(dstif));
		}
		else // resp
		{
			// 判断应答目标是否发送过ARP请求
			struct kernel_ip_cache *dstitem = kernel_ip_cache_find(session->arptable, dstip, 0);
			if (dstitem == NULL)
				return FLTRET_OK;

			// 保存应答方的IF、MAC等信息
			struct kernel_ip_cache *srcitem = kernel_ip_cache_find(session->arptable, srcip, 1);
			if (srcitem == NULL)
				return FLTRET_OK;
			memcpy(srcitem->mac, arp->ar_sha, sizeof(srcitem->mac));
			strncpy(srcitem->ifname, msg->ifname, sizeof(srcitem->ifname));

			// 目标IF
			strncpy(dstif, dstitem->ifname, sizeof(dstif));
		}
	}

	// ICMP
	if (ntohs(eth->h_proto) == 0x0800 && ip->protocol == 0x01)
	{
		struct icmphdr *icmp = (struct icmphdr*)((char*)ip + ip->ihl * 4);

		if (icmp->type != 8 && icmp->type != 0) // 8: req   0: resp
			return FLTRET_OK;

		srcip = ip->saddr;
		dstip = ip->daddr;
		isreq = (icmp->type == 8);
		proto = "icmp";

		if (isreq == 1)    // req
		{
			// 判断此ICMP请求是否在路由允许范围内
			struct route_item *route = gapconfig_findroute(msg->ifname, 0, 0, NULL, ntohl(dstip), 0);
			if (route == NULL)
				return FLTRET_OK;
			strncpy(dstif, route->vtyroute->outif, sizeof(dstif));
		}
		else
		{
			// 判断响应目标是否发送过ARP请求
			struct kernel_ip_cache *item = kernel_ip_cache_find(session->arptable, dstip, 0);
			if (item == NULL)
				return FLTRET_OK;
			strncpy(dstif, item->ifname, sizeof(dstif));
		}
	}

	char sip[20], dip[20];
	addr2str(srcip, sip); addr2str(dstip, dip);
	SCLogInfo("on eth %s, isreq: %d, %s->%s, dstif: %s", proto, isreq, sip, dip, dstif);

	// 转发给另一端
	if (dstif[0] != 0)
	{
		tlvbox_put_string_fmt(hdr->tlv_out, TLV_COMM_STRDATA, "%s %s", msg->ifname, dstif);
		buffer_sendtofwd(hdr, msg->data, msg->len);
	}
	return FLTRET_OK;
}

enum FLT_RET kernel_onfwdpkt(struct filter_header *hdr, const ForwardObject *obj)
{
	struct kernel_session *session = hdr->user;
	struct ethhdr *eth = (struct ethhdr*)obj->buffdata.data;
	struct _arphdr *arp = (struct _arphdr*)((char*)eth + sizeof(*eth));
	struct iphdr *ip = (struct iphdr*)((char*)eth + sizeof(*eth));
	uint32_t isreq = 0, srcip = 0, dstip = 0;

	char dstif[20] = { 0 };
	char *proto = "";

	// ARP
	if (ntohs(eth->h_proto) == 0x0806)
	{
		if (ntohs(arp->ar_op) != 1 && ntohs(arp->ar_op) != 2)	// 1: req   2: resp
			return FLTRET_OK;

		srcip = *((uint32_t*)arp->ar_sip);
		dstip = *((uint32_t*)arp->ar_tip);
		isreq = (ntohs(arp->ar_op) == 1);

		assert(obj->strdata != NULL);
		char *if1 = obj->strdata;
		char *if2 = strchr(if1, ' '); *if2 = '\0'; if2++;

		if (isreq == 1) // arp req
		{

			// 保存请求方的IP、IF、MAC信息
			struct kernel_ip_cache *srcitem = kernel_ip_cache_find(session->arptable, srcip, 1);
			if (srcitem == NULL)
				return FLTRET_OK;
			memcpy(srcitem->mac, arp->ar_sha, 6);
			strncpy(srcitem->ifname, if1, sizeof(srcitem->ifname));

			// 修改数据包MAC地址
			struct interface *ifp = gapconfig_get_if_by_name(if2);
			if (ifp == NULL)
				return FLTRET_OK;
			memcpy(eth->h_source, if_get_mac(ifp), 6);
			memcpy(arp->ar_sha, if_get_mac(ifp), 6);

			// 目标IF
			strncpy(dstif, if2, sizeof(dstif));
		}
		else // arp resp
		{
			// 判断应答目标是否发送过ARP请求
			struct kernel_ip_cache *dstitem = kernel_ip_cache_find(session->arptable, dstip, 0);
			if (dstitem == NULL)
				return FLTRET_OK;

			// 保存应答方的IP、IF、MAC信息
			struct kernel_ip_cache *srcitem = kernel_ip_cache_find(session->arptable, srcip, 1);
			if (srcitem == NULL)
				return FLTRET_OK;
			memcpy(srcitem->mac, arp->ar_sha, 6);
			strncpy(srcitem->ifname, if1, sizeof(srcitem->ifname));

			// 修改数据包MAC地址
			struct interface *ifp = gapconfig_get_if_by_name(dstitem->ifname);
			if (ifp == NULL)
				return FLTRET_OK;
			memcpy(eth->h_source, if_get_mac(ifp), 6);
			memcpy(arp->ar_sha, if_get_mac(ifp), 6);
			memcpy(eth->h_dest, dstitem->mac, 6);
			memcpy(arp->ar_tha, dstitem->mac, 6);

			// 目标IF
			strncpy(dstif, dstitem->ifname, sizeof(dstif));
		}
		proto = "arp";
	}

	// ICMP
	if (ntohs(eth->h_proto) == 0x0800 && ip->protocol == 0x01)
	{
		struct icmphdr *icmp = (struct icmphdr*)((char*)ip + ip->ihl * 4);
		if (icmp->type != 8 && icmp->type != 0)	// 8: req   0: resp
			return FLTRET_OK;

		srcip = ip->saddr;
		dstip = ip->daddr;
		isreq = (icmp->type == 8);

		assert(obj->strdata != NULL);
		char *if1 = obj->strdata;
		char *if2 = strchr(if1, ' '); *if2 = '\0'; if2++;

		if (isreq == 1)
		{
			struct kernel_ip_cache *dstitem = kernel_ip_cache_find(session->arptable, dstip, 0);
			if (dstitem == NULL)
				return FLTRET_OK;
			struct interface *ifp = gapconfig_get_if_by_name(if2);
			if (ifp == NULL)
				return FLTRET_OK;
			memcpy(eth->h_source, if_get_mac(ifp), 6);
			memcpy(eth->h_dest, dstitem->mac, 6);
			strncpy(dstif, dstitem->ifname, sizeof(dstif));
		}
		else
		{
			struct kernel_ip_cache *item = kernel_ip_cache_find(session->arptable, dstip, 0);
			if (item == NULL)
				return FLTRET_OK;
			struct interface *ifp = gapconfig_get_if_by_name(item->ifname);
			if (ifp == NULL)
				return FLTRET_OK;
			memcpy(eth->h_source, if_get_mac(ifp), 6);
			memcpy(eth->h_dest, item->mac, 6);
			strncpy(dstif, item->ifname, sizeof(dstif));
		}

		proto = "icmp";
	}

	// ok
	if (dstif[0] != 0)
	{
		char sip[20], dip[20];
		addr2str(srcip, sip); addr2str(dstip, dip);
		SCLogInfo("on fwd %s, isreq: %d, %s->%s, dstif: %s", proto, isreq, sip, dip, dstif);

		strncpy(hdr->dstif, dstif, sizeof(hdr->dstif));
		hdr->reqcb(hdr, obj->buffdata.data, obj->buffdata.len);

		// 启用本机的ARP、ICMP抓包功能
		int vtyhlp_enable_arpicmp(const char *ifname, int enable);  // in main_inouter.c
		vtyhlp_enable_arpicmp(hdr->dstif, 1);
	}
}


enum FLT_RET kernel_onnatpkt_udp(struct filter_header *hdr, struct nl_kerne_report_msg *msg)
{
	struct kernel_session *session = hdr->user;
	struct ethhdr *eth = (struct ethhdr*)msg->data;
	struct iphdr *iph = (struct iphdr*)((char*)eth + sizeof(*eth));
	struct udphdr *udph = (struct udphdr*)((char*)iph + iph->ihl * 4);

	uint16_t natport = 0;
	struct server *svr = NULL;
	struct route_item *route = NULL;
	int ret, ok = 0;
	do
	{
		struct interface *ifp = gapconfig_get_if_by_name(msg->ifname);
		if (ifp == NULL || if_get_vip(ifp) == 0)
			break;
		if (iph->daddr == if_get_ip(ifp) || iph->daddr == if_get_vip(ifp))
			break;
		char localip[20]; addr2str(if_get_vip(ifp), localip);
		char dstip[20];	addr2str(iph->daddr, dstip);

		gapconfig_lock();
		svr = gapconfig_get_datasvr(dstip, ntohs(udph->dest));
		gapconfig_unlock();

		if (svr == NULL)
		{
			route = gapconfig_findroute(msg->ifname, ntohl(iph->saddr), ntohs(udph->source), NULL, ntohl(iph->daddr), ntohs(udph->dest));
			if (route == NULL)
				break;

			svr = server_new(SVR_ID_UDP, UDP_SVR_NAME, localip, 0, dstip, ntohs(udph->dest)); //  这里添加的server，会在main_inouter::natserver_checktimeout中进行释放
			if (svr == NULL)
				break;
			svr->route = route;
			svr->type = SVR_TYPE_INTERNAL_NAT;

			gapconfig_lock();
			gapconfig_addserver(route, svr);
			gapconfig_unlock();
		}
		else
		{
			svr->type = SVR_TYPE_INTERNAL_DATA;
		}
		natport = natport_get(session, svr->localip, SOCK_DGRAM);
		if (natport == 0)
			break;
		svr->localport = natport;

		ret = hdr->svr_add_cb(hdr, svr);
		SCLogInfo("on nat, add svr %s:%d -> %s:%d", svr->localip, svr->localport, svr->dstip, svr->dstport);
		if (ret != 0)
			break;

		server_setfreecb(svr, natport_onsvrfree, session);	// server释放后，把对应的端口还回去
		addnat(svr->dstip, svr->dstport, svr->localip, svr->localport, 1);

		ok = 1;

	} while (0);

	if (ok == 0)
	{
		if (natport > 0)
			natport_put(session, natport);

		if (svr != NULL && route != NULL)
		{
			gapconfig_lock();
			gapconfig_removeserver(route, svr);
			gapconfig_unlock();
			server_free(svr);
		}
	}
	return FLTRET_OK;
}

enum FLT_RET kernel_onnatpkt_tcp(struct filter_header *hdr, struct nl_kerne_report_msg *msg)
{
	struct kernel_session *session = hdr->user;
	struct ethhdr *eth = (struct ethhdr*)msg->data;
	struct iphdr *iph = (struct iphdr*)((char*)eth + sizeof(*eth));
	struct tcphdr *tcph = (struct tcphdr*)((char*)iph + iph->ihl * 4);

	uint16_t natport = 0;
	struct server *svr = NULL;
	struct route_item *route = NULL;
	int ret, ok = 0;
	do
	{
		struct interface *ifp = gapconfig_get_if_by_name(msg->ifname);
		if (ifp == NULL || if_get_vip(ifp) == 0)
		{
			SCLogInfo("on nat, get eth vip failed: %s", msg->ifname);
			break;
		}
		char localip[20]; addr2str(if_get_vip(ifp), localip);
		char dstip[20];	addr2str(iph->daddr, dstip);

		gapconfig_lock();
		svr = gapconfig_get_datasvr(dstip, ntohs(tcph->dest));
		gapconfig_unlock();

		if (svr == NULL)
		{
			route = gapconfig_findroute(msg->ifname, ntohl(iph->saddr), ntohs(tcph->source), NULL, ntohl(iph->daddr), ntohs(tcph->dest));
			if (route == NULL)
			{
				SCLogInfo("on nat, not found route: %p %p %p %p", iph->saddr, tcph->source, iph->daddr, tcph->dest);
				break;
			}
			strncpy(localip, route->vtyroute->entryip, sizeof(localip));

			svr = server_new(SVR_ID_TCP, NAT_SVR_NAME, localip, 0, dstip, ntohs(tcph->dest)); //  这里添加的server，会在main_inouter::natserver_checktimeout中进行释放
			if (svr == NULL)
			{
				SCLogInfo("on nat, malloc server failed: %s:%d -> %s:%d", localip, 0, dstip, ntohs(tcph->dest));
				break;
			}
			svr->route = route;
			svr->type = SVR_TYPE_INTERNAL_NAT;

			gapconfig_lock();
			gapconfig_addserver(route, svr);
			gapconfig_unlock();
		}
		else
		{
			svr->type = SVR_TYPE_INTERNAL_DATA;
		}

		natport = natport_get(session, svr->localip, SOCK_STREAM);
		if (natport == 0)
		{
			SCLogInfo("on nat, get rand natport failed: %s", svr->localip);
			break;
		}
		svr->localport = natport;

		ret = hdr->svr_add_cb(hdr, svr);
		SCLogInfo("on nat, add svr %s:%d -> %s:%d", svr->localip, svr->localport, svr->dstip, svr->dstport);
		if (ret != 0)
			break;

		server_setfreecb(svr, natport_onsvrfree, session);	// server释放后，把对应的端口还回去
		addnat(svr->dstip, svr->dstport, svr->localip, svr->localport, 0);

		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (natport > 0)
			natport_put(session, natport);

		if (svr != NULL && route != NULL)
		{
			gapconfig_lock();
			gapconfig_removeserver(route, svr);
			gapconfig_unlock();
			server_free(svr);
		}
	}

	return FLTRET_OK;
}

enum FLT_RET kernel_onnatpkt(struct filter_header *hdr, struct nl_kerne_report_msg *msg)
{
	struct kernel_session *session = hdr->user;

	struct iphdr *iph = (struct iphdr*)((char*)msg->data + 14);

	if (msg->type == NLRPT_NAT && iph->protocol == IPPROTO_UDP)
		return kernel_onnatpkt_udp(hdr, msg);

	if (msg->type == NLRPT_NAT && iph->protocol == IPPROTO_TCP)
		return kernel_onnatpkt_tcp(hdr, msg);

	return FLTRET_OK;
}


enum FLT_RET kernel_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct kernel_session *session = hdr->user;
	if (hdr->user == NULL)
	{
		session = SCMalloc(sizeof(struct kernel_session));
		session->arptable = HashListTableInit(1000, kernel_hashlist_ipcache_hash, kernel_hashlist_ipcache_compare, kernel_hashlist_ipcache_onfree);

		INIT_LIST_HEAD(&session->freeports);
		INIT_LIST_HEAD(&session->usedports);

		int cnt = g_gapcfg->port_nat_end - g_gapcfg->port_nat_begin; assert(cnt > 0);
		session->port2item = array_init(cnt);
		for (int i = 0; i < cnt; i++)
		{
			struct port_item *item = SCMalloc(sizeof(struct port_item));
			item->port = i;
			list_add_tail(&item->_entry, &session->freeports);

			array_setat(session->port2item, i, item);
		}
		hdr->user = session;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONFWDDATA 收到外端机的数据
	if (ev == FLTEV_ONFWDDATA)
	{
		const ForwardObject *obj = buff; assert(len == sizeof(obj));
		if (obj->cmd == FWDCMD_FORWARDDATA)
		{
			assert(obj->has_buffdata);

			kernel_onfwdpkt(hdr, obj);
			return FLTRET_OK;
		}

		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSOCKDATA 收到抓包的数据
	if (ev == FLTEV_ONSOCKDATA)
	{
		struct nl_kerne_report_msg *msg = (void*)buff; assert(len == sizeof(msg));

		if (msg->type == NLRPT_PACKET)
			kernel_oncappkt(hdr, msg);
		else if (msg->type == NLRPT_NAT)
			kernel_onnatpkt(hdr, msg);
		return FLTRET_OK;
	}

	if (ev == FLTEV_ONSOCKERROR)
	{
		if (session != NULL)
		{
			for (int i = 0; i < array_count(session->port2item); i++)
			{
				void *p = array_getat(session->port2item, i);
				SCFree(p);
			}
			HashListTableFree(session->arptable);
			SCFree(session);
		}
		return FLTRET_CLOSE;
	}
	return FLTRET_OK;
}

int kernel_oninit()
{
	return 0;
}

int kernel_onfree()
{
	return 0;
}

static struct packet_filter g_filter_kernel = {
	SVR_ID_PCAP,
	"kernel parser", kernel_oninit, kernel_ondata, kernel_onfree };

PROTOCOL_FILTER_OP(kernel)
