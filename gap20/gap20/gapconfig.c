#include "app_common.h"
#include "gapconfig.h"
#include "oscall.h"
#include "gap_ctl.h"
#include "servers.h"
#include "gap_cmd_timemgr.h"
#include "if.h"
#include "prefix.h"

struct gap_config *g_gapcfg = NULL;
static pthread_mutex_t g_gaplock;

static uint32_t data_server_hash(struct HashListTable_ *tb, void *ptr, uint16_t sz)
{
	struct server *svr = ptr;
	return svr->dstport % tb->array_size;
}
static char data_server_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct server *svr1 = p1;
	struct server *svr2 = p2;
	if (svr1->dstport == svr2->dstport && strcmp(svr1->dstip, svr2->dstip) == 0)
		return 1;
	return 0;
}

static void data_server_free(void *ptr)
{
}

int gapconfig_init()
{
	int ret;
	g_gapcfg = SCMalloc(sizeof(struct gap_config));
	if (g_gapcfg == NULL)
		return -1;
	memset(g_gapcfg, 0, sizeof(*g_gapcfg));
	g_gapcfg->service_enabled = 1;
	g_gapcfg->eths = array_init(1);
	g_gapcfg->data_svrs = HashListTableInit(100, data_server_hash, data_server_compare, data_server_free);

	ret = pthread_mutex_init(&g_gaplock, NULL);
	if (ret != 0)
		SCFree(g_gapcfg);

	return ret;
}

int gapconfig_free()
{
	if (g_gapcfg == NULL)
		return 0;

	// TODO free gapconfig
	return 0;
}

void gapconfig_lock()
{
	pthread_mutex_lock(&g_gaplock);
}
void gapconfig_unlock()
{
	pthread_mutex_unlock(&g_gaplock);
}

char* intip_ntoa(uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	return inet_ntoa(addr);
}

int gapconfig_dump()
{
	printf("-------gap config dump begin-------\n");

	printf("ethcount: %d\n", array_count(g_gapcfg->eths));
	{
		for (int i = 0; i < array_count(g_gapcfg->eths); i++)
		{
			struct interface *ifp = array_getat(g_gapcfg->eths, i);

			char strip[20], strvip[20], strmask[20], strvmask[20];
			addr2str(if_get_ip(ifp), strip);
			addr2str(if_get_mask(ifp), strmask);
			addr2str(if_get_vip(ifp), strvip);
			addr2str(if_get_vmask(ifp), strvmask);

			printf("eth[%d], name: %s\n", i, ifp->name);
			printf("eth[%d], mac: %02x:%02x:%02x:%02x:%02x:%02x\n", i, ifp->hw_addr[0], ifp->hw_addr[1], ifp->hw_addr[2], ifp->hw_addr[3], ifp->hw_addr[4], ifp->hw_addr[5]);
			printf("eth[%d], ip: %s\n", i, strip);
			printf("eth[%d], mask: %s\n", i, strmask);
			printf("eth[%d], vip: %s\n", i, strvip);
			printf("eth[%d], vmask: %s\n", i, strvmask);

			printf("eth[%d], routes: %d\n", i, array_count(if_get_routes(ifp)));
			for (int j = 0; j < array_count(if_get_routes(ifp)); j++)
			{
				struct route_item *item = array_getat(if_get_routes(ifp), j);

				struct list_head *tmp;
				char ip1[20], ip2[20];

				printf("route %d: \n", j);
				printf("name: %s\n", item->vtyroute->name);
				printf("proto: %s\n", item->vtyroute->proto);
				printf("srcif: %s\n", item->vtyroute->inif);
				printf("dstif: %s\n", item->vtyroute->outif);
				printf("in_port: %d\n", item->in_port);

				if (item->vtyroute->sip_group != NULL)
				{
					for (int k = 0; k < item->vtyroute->sip_group->num; k++)
					{
						struct ip_range *range = &item->vtyroute->sip_group->ir[k];
						addr2str(htonl(range->first_ip), ip1); addr2str(htonl(range->second_ip), ip2);
						printf("src_ips: %s-%s\n", ip1, ip2);
					}
				}

				if (item->src_ports != NULL)
				{
					list_for_each(tmp, item->src_ports)
					{
						struct ipport_range *range = list_entry(tmp, struct ipport_range, _entry);
						printf("src_ports: %d-%d\n", range->begin, range->end == UINT_MAX ? 65535 : range->end);
					}
				}

				if (item->vtyroute->dip_group != NULL)
				{
					for (int k = 0; k < item->vtyroute->dip_group->num; k++)
					{
						struct ip_range *range = &item->vtyroute->dip_group->ir[k];
						addr2str(htonl(range->first_ip), ip1); addr2str(htonl(range->second_ip), ip2);
						printf("dst_ips: %s-%s\n", ip1, ip2);
					}
				}

				if (item->dst_ports != NULL)
				{
					list_for_each(tmp, item->dst_ports)
					{
						struct ipport_range *range = list_entry(tmp, struct ipport_range, _entry);
						printf("dst_ports: %d-%d\n", range->begin, range->end == UINT_MAX ? 65535 : range->end);
					}
				}
			}
		}
	}

	printf("port_ftp_begin: %d\n", g_gapcfg->port_ftp_begin);
	printf("port_ftp_end: %d\n", g_gapcfg->port_ftp_end);

	printf("port_nat_begin: %d\n", g_gapcfg->port_nat_begin);
	printf("port_nat_end: %d\n", g_gapcfg->port_nat_end);

	printf("port_opc_begin: %d\n", g_gapcfg->port_opc_begin);
	printf("port_opc_end: %d\n", g_gapcfg->port_opc_end);

	printf("port_sip_begin: %d\n", g_gapcfg->port_sip_begin);
	printf("port_sip_end: %d\n", g_gapcfg->port_sip_end);

	printf("limit_sockcache: %d\n", g_gapcfg->limit_sockcache);
	printf("limit_usercount: %d\n", g_gapcfg->limit_usercount);

	printf("timeout_session: %d\n", g_gapcfg->timeout_session);

	printf("-------gap config dump ok-------\n");

	return 0;
}

struct route_item* gapconfig_newroute()
{
	struct route_item *ret = SCMalloc(sizeof(struct route_item));
	if (ret == NULL)
		return NULL;
	memset(ret, 0, sizeof(*ret));
	ret->servers = array_init(1);
	return ret;
}

void gapconfig_freeroute(struct route_item* route)
{
	if (route == NULL)
		return;
	if (route->src_ports != NULL)
		gapconfig_free_ragelist(route->src_ports);
	if (route->dst_ports != NULL)
		gapconfig_free_ragelist(route->dst_ports);
	SCFree(route);
}

int gapconfig_addroute(struct interface *ifp, struct route_item *route)
{
	if (ifp == NULL || route == NULL)
		return -1;
	route->inifp = if_lookup_by_name(route->vtyroute->inif);
	route->outifp = if_lookup_by_name(route->vtyroute->outif);
	array_add(if_get_routes(ifp), route);
	return 0;
}

struct route_item* gapconfig_getroutebyname(struct interface *ifp, const char *name)
{
	if (ifp == NULL || name == NULL)
		return NULL;

	struct route_item *ret = NULL;

	for (int i = 0; i < array_count(if_get_routes(ifp)); i++)
	{
		struct route_item *item = array_getat(if_get_routes(ifp), i);
		if (strcmp(item->vtyroute->name, name) == 0)
		{
			ret = item;
			break;
		}
	}

	return ret;
}

int gapconfig_removeroute(struct interface *ifp, struct route_item *route)
{
	if (ifp == NULL)
		return -1;
	int ret = array_find_and_remove(if_get_routes(ifp), route);
	return (ret == -1) ? -1 : 0;
}

int gapconfig_interface_initext(struct interface *ifp)
{
	struct if_ext *ext = SCMalloc(sizeof(struct if_ext));
	memset(ext, 0, sizeof(*ext));
	ext->ips = array_init(1);
	ext->vips = array_init(1);
	ext->routes = array_init(1);
	ifp->info = ext;
	//SCLogInfo("init interface %s's ext: %p, ips: %p, vips: %p, routes: %p", ifp->name, ext, ext->ips, ext->vips, ext->routes);
	return 0;
}

void gapconfig_interface_freeext(struct interface *ifp)
{
	struct if_ext *ext = ifp->info;
	if (ext)
	{
		if (ext->ips != NULL)
		{
			array_free(ext->ips);
			ext->ips = NULL;
		}

		if (ext->vips != NULL)
		{
			array_free(ext->vips);
			ext->vips = NULL;
		}
		
		if (ext->routes != NULL)
		{
			array_free(ext->routes);
			ext->routes = NULL;
		}
		
		SCFree(ext);
		ifp->info = NULL;
	}
}

struct ipport_range* rangelist_match(struct range_list *lst, uint32_t n)
{
	if (lst == NULL)
		return NULL;

	struct list_head *iter; list_for_each(iter, lst)
	{
		struct ipport_range *item = list_entry(iter, struct ipport_range, _entry);
		if (n >= item->begin && n <= item->end)
			return item;
	}
	return NULL;
}

struct ip_range* vtyiplist_match(struct gap_ipgroup *group, uint32_t n)
{
	if (group == NULL)
		return NULL;

	struct ip_range *ret = NULL;
	ipgroup_lock();
	for (int i = 0; i < group->num; i++)
	{
		if (n >= group->ir[i].first_ip && n <= group->ir[i].second_ip)
		{
			ret = &group->ir[i];
			break;
		}
	}
	ipgroup_unlock();
	return ret;
}

struct route_item* gapconfig_findroute(const char *sif, uint32_t saddr, uint16_t sport, const char *dif, uint32_t daddr, uint16_t dport)
{
	struct route_item *ret = NULL;

	struct interface *sifp = NULL;
	struct interface *difp = NULL;

	if (sif != NULL)
		sifp = if_lookup_by_name(sif);
	if (difp != NULL)
		difp = if_lookup_by_name(dif);
	if (sifp == NULL)
		return NULL;

	for (int i = 0; i < array_count(if_get_routes(sifp)); i++)
	{
		struct route_item *item = array_getat(if_get_routes(sifp), i);

		if (sif != NULL && item->inifp != sifp)
			continue;
		if (dif != NULL && item->outifp != difp)
			continue;

		if (saddr != 0 && vtyiplist_match(item->vtyroute->sip_group, saddr) == NULL)
			continue;
		if (daddr != 0 && vtyiplist_match(item->vtyroute->dip_group, daddr) == NULL)
			continue;
		if (sport != 0 && rangelist_match(item->src_ports, sport) == NULL)
			continue;
		if (dport != 0 && rangelist_match(item->dst_ports, dport) == NULL)
			continue;

		ret = item;
		break;
	}
	return ret;
}

int gapconfig_route_hastrans_tcp(struct interface *ifp)
{
	for (int i = 0; i < array_count(if_get_routes(ifp)); i++)
	{
		struct route_item *item = array_getat(if_get_routes(ifp), i);
		if (ROUTE_IS_TRANSPARENT(item->in_port) == 0)
			continue;

		for (int j = 0; j < countof(item->svrids); j++)
		{
			if (item->svrids[j] == 1 && SVRID_IS_TCP_FAMILY(j))
				return 1;
		}
	}
	return 0;
}

int gapconfig_route_hastrans_udp(struct interface *ifp)
{
	for (int i = 0; i < array_count(if_get_routes(ifp)); i++)
	{
		struct route_item *item = array_getat(if_get_routes(ifp), i);
		if (ROUTE_IS_TRANSPARENT(item->in_port) == 0)
			continue;

		for (int j = 0; j < countof(item->svrids); j++)
		{
			if (item->svrids[j] == 1 && SVRID_IS_UDP_FAMILY(j))
				return 1;
		}
	}
	return 0;
}

uint32_t ipport2int(const char *str)
{
	if (strchr(str, '.'))   // IP
		return ntohl(inet_addr(str));
	return atoi(str);
}

struct range_list* gapconfig_parse_range_str(const char *str)
{
	char *s = NULL;
	char  *iter, *ctx, *p;
	struct range_list *ret = NULL;
	struct ipport_range *item = NULL;

	ret = SCMalloc(sizeof(*ret));
	if (ret == NULL)
		goto ERR;
	INIT_LIST_HEAD(ret);

	// ALL
	if (str[0] == '0' || str[0] == '*')
	{
		item = SCMalloc(sizeof(*item));
		if (item == NULL)
			goto ERR;

		item->begin = 0;
		item->end = UINT_MAX;
		list_add_tail(&item->_entry, ret);
		return ret;
	}

	// single ip/port
	if (strchr(str, ';') == NULL && strchr(str, '-') == NULL)
	{
		item = SCMalloc(sizeof(*item));
		if (item == NULL)
			goto ERR;

		item->begin = item->end = ipport2int(str);
		list_add_tail(&item->_entry, ret);
		return ret;
	}

	// multi ip/ports£º192.168.40.100-192.168.40.200 / 1-65535 / 192.168.40.10-192.168.40.30;192.168.40.100-192.168.40.200;192.168.40.222 / 1-10;15;20-30;45
	s = SCStrdup(str);
	if (s == NULL)
		goto ERR;
	for (iter = strtok_s(s, ";", &ctx); iter != NULL; iter = strtok_s(NULL, ";", &ctx))
	{
		item = SCMalloc(sizeof(*item));
		if (item == NULL)
			goto ERR;
		INIT_LIST_HEAD(&item->_entry);

		p = strchr(iter, '-');
		if (p == NULL)  // one ip/port
		{
			item->begin = item->end = ipport2int(iter);
		}
		else
		{   // ip/port range
			*p = 0; p++;
			item->begin = ipport2int(iter);
			item->end = ipport2int(p);
		}
		list_add_tail(&item->_entry, ret);
	}
	SCFree(s);
	return ret;

ERR:
	if (s)
		SCFree(s);
	if (ret)
		gapconfig_free_ragelist(ret);
	SCLogInfo("in gapconfig_parse_range_str, parse range_string failed: %s", str);
	return NULL;
}

void gapconfig_free_ragelist(struct range_list *lst)
{
	struct list_head *iter, *next;
	list_for_each_safe(iter, next, lst)
	{
		struct ipport_range *item = list_entry(iter, struct ipport_range, _entry);
		list_del(iter);
		SCFree(item);
	}
	SCFree(lst);
}

int gapconfig_ifname2n(const char *ifname)
{
	struct interface *ifp = if_get_by_name(ifname);
	if (ifp == NULL)
		return -1;
	return ifp->ifindex;
}

int gapconfig_addserver(struct route_item *route, struct server *svr)
{
	if (route == NULL || svr == NULL)
		return -1;

	svr->route = route;
	int ret = array_add(route->servers, svr);
	return (ret == -1) ? -1 : 0;
}

int gapconfig_removeserver(struct route_item *route, struct server *svr)
{
	if (route == NULL || svr == NULL)
		return -1;

	int ret = array_find_and_remove(route->servers, svr);
	return (ret == -1) ? -1 : 0;
}

struct array* gapconfig_findserver(struct route_item *route, struct server *templ)
{
	if (route == NULL || templ == NULL)
		return NULL;

	struct array *ret = array_init(1);
	if (ret == NULL)
		return NULL;

	for (int i = 0; i < array_count(route->servers); i++)
	{
		struct server *svr = array_getat(route->servers, i);

		if (templ != NULL)
		{
			if (templ->id != _SVR_ID_NONE && svr->id != templ->id)
				continue;
			if (templ->type != _SVR_TYPE_NONE && svr->type != templ->type)
				continue;
			if (templ->name != NULL && svr->name != NULL && strcmp(svr->name, templ->name) != 0)
				continue;
			if (templ->localip != NULL && svr->localip != NULL && strcmp(svr->localip, templ->localip) != 0)
				continue;
			if (templ->localport != 0 && svr->localport != templ->localport)
				continue;
			if (templ->dstip != NULL && svr->dstip != NULL && strcmp(svr->dstip, templ->dstip) != 0)
				continue;
			if (templ->dstport != 0 && svr->dstport != templ->dstport)
				continue;
			if (templ->route != NULL && svr->route != templ->route)
				continue;
		}

		array_add(ret, svr);
	}
	return ret;
}

struct array* gapconfig_getserver_byaddr(struct interface *ifp, const char *localip)
{
	struct array *ret = array_init(1);
	if (ret == NULL)
		return NULL;

	struct array *routes = if_get_routes(ifp);

	for (int i = 0; i < array_count(routes); i++)
	{
		struct route_item *route = array_getat(routes, i);

		for (int j = 0; j < array_count(route->servers); j++)
		{
			struct server *svr = array_getat(route->servers, j);
			if (strcmp(svr->localip, localip) == 0)
				array_add(ret, svr);
		}
	}
	return ret;
}

int gapconfig_add_datasvr(struct server *svr)
{
	return HashListTableAdd(g_gapcfg->data_svrs, svr, sizeof(svr));
}

int gapconfig_remove_datasvr(struct server *svr)
{
	return HashListTableRemove(g_gapcfg->data_svrs, svr, sizeof(svr));
}

struct server* gapconfig_get_datasvr(const char *dstip, uint16_t dstport)
{
	struct server tmp = { 0 };
	tmp.dstip = (char*)dstip;
	tmp.dstport = dstport;
	return HashListTableLookup(g_gapcfg->data_svrs, &tmp, sizeof(&tmp));
}

uint32_t if_get_ip(struct interface *ifp)
{
	struct array *ips = ((struct if_ext*)ifp->info)->ips;
	if (array_count(ips) == 0)
		return 0;
	struct connected *ifcp = array_getat(ips, 0);
	return ifcp->address->u.prefix4.s_addr;
}

uint32_t if_get_mask(struct interface *ifp)
{
	struct array *ips = ((struct if_ext*)ifp->info)->ips;
	if (array_count(ips) == 0)
		return 0;
	struct connected *ifcp = array_getat(ips, 0);
	struct in_addr maskaddr;
	masklen2ip(ifcp->address->prefixlen, &maskaddr);
	return maskaddr.s_addr;
}

uint32_t if_get_vip(struct interface *ifp)
{
	struct array *ips = ((struct if_ext*)ifp->info)->vips;
	if (ips == NULL)
		return 0;
	if (array_count(ips) == 0)
		return 0;
	struct connected *ifcp = array_getat(ips, 0);
	return ifcp->address->u.prefix4.s_addr;
}

uint32_t if_get_vmask(struct interface *ifp)
{
	struct array *ips = ((struct if_ext*)ifp->info)->vips;
	if (array_count(ips) == 0)
		return 0;
	struct connected *ifcp = array_getat(ips, 0);
	struct in_addr maskaddr;
	masklen2ip(ifcp->address->prefixlen, &maskaddr);
	return maskaddr.s_addr;
}

struct connected* if_get_vip_at(struct interface *ifp, int n)
{
	struct if_ext *ext = ifp->info;
	if (ext == NULL)
		return NULL;
	return array_getat(ext->vips, n);
}

int connected_get_ipaddr(struct connected *ifcp, char *ip)
{
	addr2str(ifcp->address->u.prefix4.s_addr, ip);
	return 0;
}
