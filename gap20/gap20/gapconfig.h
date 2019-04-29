#ifndef _GAP_CONFIG_H_
#define _GAP_CONFIG_H_

#define MAX_ETH_COUNT 30
#include "util-list.h"
#include "util-array.h"
#include "servers.h"
#include "if.h"
#include "gap_cmd_route.h"

struct if_ext
{
	struct array *ips;
	struct array *vips;
	struct array *routes;
};

#define if_get_mac(ifp) ifp->hw_addr
#define if_get_routes(ifp) ((struct if_ext*)ifp->info)->routes

uint32_t if_get_ip(struct interface *ifp);
uint32_t if_get_mask(struct interface *ifp);
uint32_t if_get_vip(struct interface *ifp);
uint32_t if_get_vmask(struct interface *ifp);

// IP/port range obj, host order
struct ipport_range
{
	struct list_head _entry;
	uint32_t begin;
	uint32_t end;
};
#define range_list list_head



struct route_item
{
	uint8_t svrids[_SVR_ID_COUNT];	// ids flag array, HTTP and FTP, svrids[SVR_ID_HTTP] = 1 and svrids[SVR_ID_FTP] = 1
	uint16_t in_port;	// in_port=0, route is transparent route

	struct range_list *src_ports; // (host order)
	struct range_list *dst_ports;	// (host order)

	struct array *servers;
	struct interface *inifp;
	struct interface *outifp;
	struct gap_route *vtyroute;
};
#define ROUTE_IS_TRANSPARENT(port) (port == 0)

struct gap_config
{
	struct array *eths;

	HashListTable *data_svrs;

	char *ssl_svrcacrt;			// path of server_ca.crt
	char *ssl_svrcrt;			// path of server.crt
	char *ssl_svrkey;			// path of server.key

	uint16_t port_ftp_begin;
	uint16_t port_ftp_end;

	uint16_t port_udp_begin;	//udp port
	uint16_t port_udp_end;
	uint16_t port_rtsp_begin;	//udp port
	uint16_t port_rtsp_end;		//udp port

	uint16_t port_nat_begin;
	uint16_t port_nat_end;

	uint16_t port_opc_begin;
	uint16_t port_opc_end;

	uint16_t port_sip_begin;
	uint16_t port_sip_end;

	uint32_t limit_sockcache;
	uint32_t limit_usercount;

	uint32_t timeout_session;

	/* login permission ctl */
	uint8_t ssh_login_permission;
	uint8_t console_login_permission;

	uint8_t service_enabled;
};

#define gapconfig_get_if_by_name if_get_by_name

int gapconfig_init();
int gapconfig_free();
int gapconfig_dump();


void gapconfig_lock();
void gapconfig_unlock();

int gapconfig_interface_initext(struct interface *ifp);
void gapconfig_interface_freeext(struct interface *ifp);


// create route item
struct route_item* gapconfig_newroute();

// add route item
int gapconfig_addroute(struct interface *eth, struct route_item *route);

// remove route item
int gapconfig_removeroute(struct interface *eth, struct route_item *route);

// free route item
void gapconfig_freeroute(struct route_item* route);



// get route_item by route name
struct route_item* gapconfig_getroutebyname(struct interface *eth, const char *name);

// find route on routelist£¬args set to NULL/0 means igonre the args; (host order)
struct route_item* gapconfig_findroute(const char *sif, uint32_t saddr, uint16_t sport, const char *dif, uint32_t daddr, uint16_t dport);

// check route list, find has transparent route
int gapconfig_route_hastrans_tcp(struct interface *eth);
int gapconfig_route_hastrans_udp(struct interface *eth);




// parse a range string(eg: 192.168.40.100-192.168.40.200 / 1-65535 / 192.168.40.10-192.168.40.30;192.168.40.100-192.168.40.200;192.168.40.222 / 1-10;15;20-30;45)
struct range_list* gapconfig_parse_range_str(const char *str);

// free range_list
void gapconfig_free_ragelist(struct range_list *range);

// check n is in list
struct ipport_range* rangelist_match(struct range_list *lst, uint32_t n);

// check n is in vty's ipgroup
struct ip_range* vtyiplist_match(struct gap_ipgroup *group, uint32_t n);




int gapconfig_ifname2n(const char *ifname);

// add server to gapconfig
int gapconfig_addserver(struct route_item *route, struct server *svr);

// remove server from gapconfig
int gapconfig_removeserver(struct route_item *route, struct server *svr);

// find server by templ
struct array* gapconfig_findserver(struct route_item *route, struct server *templ);

// get eth's server list
struct array* gapconfig_getserver_byaddr(struct interface *ifp, const char *localip);


// add data server
int gapconfig_add_datasvr(struct server *svr);

// remove data server
int gapconfig_remove_datasvr(struct server *svr);

// get data server
struct server* gapconfig_get_datasvr(const char *dstip, uint16_t dstport);


extern struct gap_config *g_gapcfg;

#endif
