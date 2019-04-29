#ifndef _GAP_CMD_ROUTE_H
#define _GAP_CMD_ROUTE_H
#include "util-list.h"
#include "util-mem.h"
#include "oscall.h"
#include "gap_cmd.h"
#include "gap_cmd_timemgr.h"

struct gap_ipgroup
{
	struct list_head n_list;
	char name[NAME_LEN + 1];
	char ipset[IPSET_LEN];/*eg: "192.168.1.3;192.168.4.1-192.168.4.5;192.168.5.0/24" */

	/* ipset */
	struct ip_range ir[MAX_IPRANGE_SIZE];
	int num;
	int level;
};

struct gap_route
{
	struct list_head n_list;
	char name[NAME_LEN + 1];
	char proto[PROTO_LEN*PROTO_NUM];/* support four protocols */
	char sip[NAME_LEN];/* name of ipgroup */
	struct gap_ipgroup *sip_group;
	char sport[PORT_LEN*PORT_NUM];/* support 24 ports */
	char dip[NAME_LEN];/* name of ipgroup */
	struct gap_ipgroup *dip_group;
	char dport[PORT_LEN*PORT_NUM];/* support 24 ports */
	char outif[IFNAME_LEN];
	char inif[IFNAME_LEN];
	char entryip[IPV4_LEN];
	char inport[PORT_LEN];

	/* time acl */
	char effectime[NAME_LEN + sizeof(TIME_GROUP_SUFFIX)];
	struct time_acl tacl;
};

struct gap_rt
{
	struct list_head n_list;
	char name[NAME_LEN];
	char dip[NAME_LEN];/* name of ipgroup */
	struct gap_ipgroup *dip_group;
	char outif[IFNAME_LEN];
	struct gap_interface *gi;
	struct interface *ifp;
	char *rt_cmd_stuffix[MAX_RT];
};

void route_conf_cmd_init(void);
void route_show_cmd_init(unsigned int machine);
void route_init(void);
void route_exit(void);

#endif 
