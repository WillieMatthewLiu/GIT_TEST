
#include "app_common.h"

#include <zebra.h>

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/types.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/time.h>

#include <readline/readline.h>
#include <readline/history.h>
#include <termios.h>
#include "command.h"
#include "memory.h"
#include "buffer.h"
#include "log.h"
#include "if.h"
#include "network.h"
#include "jhash.h"
#include <pthread.h>
#include <string.h>
#include "command.h"
#include "thread.h"
#include "vty.h"
#include "swe_ver.h"
#include "ha.h"
#include "gap_ctl_ha.h"

#include "gap_ctl.h"
#include "gap_ctl_adapter.h"
#include "main_inouter.h"
#include "gap_cmd_route.h"
#include "prefix.h"
#include "gapconfig.h"

static int vty_onroute_add(struct gap_route *oldroute, struct gap_route *newroute);
static int vty_onroute_edit(struct gap_route *oldroute, struct gap_route *newroute);
static int vty_onroute_del(struct gap_route *oldroute, struct gap_route *newroute);

route_fun rfun[op_max] = { vty_onroute_add, vty_onroute_edit, vty_onroute_del, NULL };

/*
*	List: for route lookups
*/
struct list_head ipgroup_head;
struct list_head rt_head;
pthread_mutex_t rt_lock;
unsigned int rt_count = 0;

static int vty_onroute_add(struct gap_route *oldroute, struct gap_route *newroute)
{
	int ok = 0, ret;

	assert(oldroute == NULL);
	assert(newroute != NULL);

	struct interface *ifp = if_get_by_name(newroute->inif);
	if (ifp->info == NULL)
		gapconfig_interface_initext(ifp);

	SCLogInfo("on vty_onroute_add, %p, %p", newroute, ifp);

	gapconfig_lock();

	do
	{
		if (ifp == NULL)
		{
			SCLogError("on vty_onroute_add, not found %s's ethconfig", newroute->inif);
			break;
		}

		if (newroute->sip_group == NULL || newroute->dip_group == NULL)
		{
			SCLogError("on vty_onroute_add, sip_group/dip_group is NULL, %p %p", newroute->sip_group, newroute->dip_group);
			break;
		}

		if (ROUTE_IS_TRANSPARENT(atoi(newroute->inport)) == 1)
		{
			ret = vty_onroute_doadd_trans(newroute, ifp);
			if (ret == 0)
				ok = 1;
		}
		else
		{
			ret = vty_onroute_doadd_mapped(newroute, ifp);
			if (ret == 0)
				ok = 1;
		}

	} while (0);

	SCLogInfo("vty_onroute_add finish, ret: %d", (ok == 1) ? 0 : -1);
	gapconfig_unlock();

	if (ok == 0)
		return -1;
	return 0;
}
static int vty_onroute_edit(struct gap_route *oldroute, struct gap_route *newroute)
{
	assert(oldroute != NULL);
	assert(newroute != NULL);

	int ok = 0;
	do
	{
		vty_onroute_del(oldroute, NULL);
		os_sleep(500);

		gapconfig_lock();

		struct interface *oldifp = gapconfig_get_if_by_name(oldroute->inif);
		struct interface *newifp = gapconfig_get_if_by_name(newroute->inif);

		if (oldifp == NULL)
		{
			SCLogError("on vty_onroute_edit, not found %s's ethconfig", oldroute->inif);
			break;
		}

		if (newifp == NULL)
		{
			SCLogError("on vty_onroute_edit, not found %s's ethconfig", newroute->inif);
			break;
		}

		SCLogInfo("on vty_onroute_edit, old: %p, %p, new: %p, %p", oldroute, oldifp, newroute, newifp);

		if (atoi(newroute->inport) == 0)
		{
			if (vty_onroute_doadd_trans(newroute, newifp) == 0)
				ok = 1;
		}
		else
		{
			if (vty_onroute_doadd_mapped(newroute, newifp) == 0)
				ok = 1;
		}

	} while (0);

	SCLogInfo("vty_onroute_edit finish, ret: %d", (ok == 1) ? 0 : -1);
	gapconfig_unlock();

	if (ok == 0)
		return -1;
	return 0;
}
static int vty_onroute_del(struct gap_route *oldroute, struct gap_route *newroute)
{
	assert(oldroute != NULL);
	assert(newroute == NULL);

	SCLogInfo("on vty_onroute, %p, %p", oldroute, newroute);

	gapconfig_lock();

	struct interface *ifp = gapconfig_get_if_by_name(oldroute->inif);

	int ok = 0;
	do
	{
		if (ifp == NULL)
		{
			SCLogError("on vty_onroute_del, not found %s's ethconfig", oldroute->inif);
			break;
		}

		struct route_item *route = gapconfig_getroutebyname(ifp, oldroute->name);
		if (route == NULL)
		{
			SCLogError("on vty_onroute_del, find route failed: %s", oldroute->name);
			break;
		}
		vtyhlp_closeall_byroute(route);
		gapconfig_removeroute(ifp, route);
		gapconfig_freeroute(route);

		// after delete all trans route, stop kernel capture
		vtyhlp_sync_kernel_capture(ifp);

		ok = 1;
	} while (0);

	SCLogInfo("on vty_onroute_del finish, ret: %d", (ok == 1) ? 0 : -1);
	gapconfig_unlock();

	if (ok == 0)
		return -1;
	return 0;
}

struct gap_ipgroup * check_ipgroup_created(char *name)
{
	struct gap_ipgroup *ipgroup;
	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(ipgroup, &ipgroup_head, n_list) {
		if (0 == strcmp(ipgroup->name, name)) {
			pthread_mutex_unlock(&rt_lock);
			return ipgroup;
		}
	}
	pthread_mutex_unlock(&rt_lock);
	return NULL;
}

int check_ipgroup_invalid(char *name, char *inport)
{
	int ret = 0;
	struct gap_ipgroup *ipgroup;
	if (atoi(inport) == 0) {
		return ret;
	}

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(ipgroup, &ipgroup_head, n_list) {
		if (0 == strcmp(ipgroup->name, name)) {
			if (ipgroup->num != 1 || ipgroup->ir[0].first_ip != ipgroup->ir[0].second_ip) {
				ret = 1;
			}
			break;
		}
	}
	pthread_mutex_unlock(&rt_lock);

	return ret;
}

static int check_ipgroup_referenced(char *name)
{
	struct gap_route *route;
	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(route, &rt_head, n_list) {
		if (0 == strcmp(route->sip, name) || 0 == strcmp(route->dip, name)) {
			pthread_mutex_unlock(&rt_lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&rt_lock);
	return 0;
}

DEFUN(gap_ctl_ipgroup_add,
	gap_ctl_ipgroup_add_cmd,
	"ipgroup add name WORD ipset WORD level (0|1|2|3)",
	"ipgroup command\n"
	"add ipgroup\n"
	"name\n"
	"name of ipgroup\n"
	"ip sets\n"
	"ip address,such as:192.168.1.1;192.168.5.0/24;192.168.8.1-192.168.8.10\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
)
{
	struct gap_ipgroup *gig, *ipgroup, *ret = NULL;

	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	ipgroup = SCMalloc(sizeof(struct gap_ipgroup));
	if (NULL == ipgroup) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	strncpy(ipgroup->name, argv[0], sizeof(ipgroup->name) - 1);
	strncpy(ipgroup->ipset, argv[1], sizeof(ipgroup->ipset) - 1);
	ipgroup->level = atoi(argv[2]);

	if (translate_ipset(ipgroup->ipset, ipgroup->ir, &ipgroup->num)) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(gig, &ipgroup_head, n_list) {
		if (0 == strcmp(gig->name, argv[0])) {
			/* HIT */
			ret = gig;
			break;
		}
	}

	if (NULL == ret) {
		list_add(&ipgroup->n_list, &ipgroup_head);
	}
	else {
		SCFree(ipgroup);
	}
	pthread_mutex_unlock(&rt_lock);

	if (ret) {
		vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipgroup_add,
	gap_ctl_ipgroup_add_o_cmd,
	"outer ipgroup add name WORD ipset WORD level (0|1|2|3)",
	"outer machine\n"
	"ipgroup command\n"
	"add ipgroup\n"
	"name\n"
	"name of ipgroup\n"
	"ip sets\n"
	"ip address,such as:192.168.1.1;192.168.5.0/24;192.168.8.1-192.168.8.10\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
);

DEFUN(gap_ctl_ipgroup_del,
	gap_ctl_ipgroup_del_cmd,
	"ipgroup delete name WORD",
	"ipgroup command\n"
	"delete ipgroup\n"
	"name\n"
	"name of ipgroup\n"
)
{
	struct gap_ipgroup *ipgroup;
	int del = 0;

	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	/*check referenced*/
	if (check_ipgroup_referenced(argv[0])) {
		vty_result(ERR_CODE_REFERENCDERR, ERR_CODE_REFERENCDERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(ipgroup, &ipgroup_head, n_list) {
		if (0 == strcmp(ipgroup->name, argv[0])) {
			/* HIT */
			list_del(&ipgroup->n_list);
			SCFree(ipgroup);
			del = 1;
			break;
		}
	}
	pthread_mutex_unlock(&rt_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipgroup_del,
	gap_ctl_ipgroup_del_o_cmd,
	"outer ipgroup delete name WORD",
	"outer machine\n"
	"ipgroup command\n"
	"delete ipgroup\n"
	"name\n"
	"name of ipgroup\n"
);

DEFUN(gap_ctl_ipgroup_view,
	gap_ctl_ipgroup_view_cmd,
	"show ipgroup {pgindex <0-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"show ipgroup.(ipgroupname ipset)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n"
)
{
	struct gap_ipgroup *ipgroup;

	SHOW_CMD_RUN();

	int count = 0;
	char *pageindex = argv[0];
	char *pagesize = argv[1];
	if (pageindex == NULL) {
		pageindex = DEFAULT_PGINDEX;
	}
	if (pagesize == NULL) {
		pagesize = DEFAULT_PGSIZE;
	}
	int pgindex = atoi(pageindex);
	int pgsize = atoi(pagesize);

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(ipgroup, &ipgroup_head, n_list) {
		if ((pgindex == 0) || (count >= ((pgindex - 1)*pgsize) && count < (pgindex*pgsize))) {
			vty_out(vty, "%s %s %d%s", ipgroup->name, ipgroup->ipset, ipgroup->level, VTY_NEWLINE);
		}
		count++;
	}
	pthread_mutex_unlock(&rt_lock);

	vty_out(vty, "[pageindex=%d,pagesize=%d,totalline=%d]%s", pgindex, pgsize, count, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipgroup_view,
	gap_ctl_ipgroup_view_o_cmd,
	"show outer ipgroup {pgindex <0-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"outer machine\n"
	"show ipgroup.(ipgroupname ipset)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n");

DEFUN(gap_ctl_ipgroup_edit,
	gap_ctl_ipgroup_edit_cmd,
	"ipgroup edit name WORD ipset WORD level (0|1|2|3)",
	"ipgroup command\n"
	"edit ipgroup\n"
	"name\n"
	"name of ipgroup\n"
	"ip sets\n"
	"ip address,such as:192.168.1.1;192.168.5.0/24;192.168.8.1-192.168.8.10\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
)
{
	struct gap_ipgroup *ipgroup, *ret = NULL;

	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(ipgroup, &ipgroup_head, n_list) {
		if (0 == strcmp(ipgroup->name, argv[0])) {
			/* HIT */
			strncpy(ipgroup->ipset, argv[1], sizeof(ipgroup->ipset) - 1);
			ipgroup->level = atoi(argv[2]);
			if (translate_ipset(ipgroup->ipset, ipgroup->ir, &ipgroup->num)) {
				vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
				pthread_mutex_unlock(&rt_lock);
				return CMD_ERR_NOTHING_TODO;
			}
			ret = ipgroup;
			break;
		}
	}
	pthread_mutex_unlock(&rt_lock);

	/* object not found */
	if (NULL == ret) {
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipgroup_edit,
	gap_ctl_ipgroup_edit_o_cmd,
	"outer ipgroup edit name WORD ipset WORD level (0|1|2|3)",
	"outer machine\n"
	"ipgroup command\n"
	"edit ipgroup\n"
	"name\n"
	"name of ipgroup\n"
	"ip sets\n"
	"ip address,such as:192.168.1.1;192.168.5.0/24;192.168.8.1-192.168.8.10\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
);

DEFUN(gap_ctl_route_add,
	gap_ctl_route_add_cmd,
	"route add routename WORD proto PROTOCOL sip WORD sport WORD dip WORD dport WORD outif INTERFACE inif INTERFACE entryip A.B.C.D inport <0-65535> {effectime WORD}",
	"route command\n"
	"add route\n"
	"routename\n"
	"name of route\n"
	"protocol\n"
	"PROTOCOL, such as: FTP,HTTP,TDCS\n"
	"source ip\n"
	"name of ipgroup\n"
	"source port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"destination ip\n"
	"name of ipgroup\n"
	"destination port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"outcoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"incoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"entry ip\n"
	"entry ip, such as:A.B.C.D\n"
	"incoming port\n"
	"0-65535\n"
	"Effective time\n"
	"name of timerange and timegroup, such as:time1, timeg1(g)\n")
{
	char *name, *proto, *sip, *sport, *dip, *dport, *outif, *inif, *entryip, *inport, *etime;
	name = argv[0];
	proto = argv[1];
	sip = argv[2];
	sport = argv[3];
	dip = argv[4];
	dport = argv[5];
	outif = argv[6];
	inif = argv[7];
	entryip = argv[8];
	inport = argv[9];
	etime = argv[10];
	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();
	return gap_cmd_impl_route_add(vty, name, proto, sip, sport, dip, dport, outif, inif, entryip, inport, etime);
}

ALIAS(gap_ctl_route_add,
	gap_ctl_route_add_o_cmd,
	"outer route add routename WORD proto PROTOCOL sip WORD sport WORD dip WORD dport WORD outif INTERFACE inif INTERFACE entryip A.B.C.D inport <0-65535> {effectime WORD}",
	"outer machine\n"
	"route command\n"
	"add route\n"
	"routename\n"
	"name of route\n"
	"protocol\n"
	"PROTOCOL, such as: FTP,HTTP,TDCS\n"
	"source ip\n"
	"name of ipgroup\n"
	"source port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"destination ip\n"
	"name of ipgroup\n"
	"destination port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"outcoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"incoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"entry ip\n"
	"entry ip, such as:A.B.C.D\n"
	"incoming port\n"
	"0-65535\n"
	"Effective time\n"
	"name of timerange and timegroup, such as:time1, timeg1(g)\n");

DEFUN(gap_ctl_route_del,
	gap_ctl_route_del_cmd,
	"route delete routename WORD",
	"route command\n"
	"delete route\n"
	"routename\n"
	"name of route\n"
)
{
	struct gap_route *route;
	int del = 0;

	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(route, &rt_head, n_list) {
		if (0 == strcmp(route->name, argv[0])) {
			/* HIT */
			if (rfun[op_del]) {
				/* Callback route function */
				if (rfun[op_del](route, NULL)) {
					pthread_mutex_unlock(&rt_lock);
					vty_result(ERR_CODE_CALLBACKERR, ERR_CODE_CALLBACKERR_DESC);
					return CMD_ERR_NOTHING_TODO;
				}
			}
			timemgr_put(&route->tacl);/* Release reference count */
			list_del(&route->n_list);
			SCFree(route);
			del = 1;
			rt_count--;
			break;
		}
	}
	pthread_mutex_unlock(&rt_lock);

	/* object not found */
	if (0 == del) {
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_route_del,
	gap_ctl_route_del_o_cmd,
	"outer route delete routename WORD",
	"outer machine\n"
	"route command\n"
	"delete route\n"
	"routename\n"
	"name of route\n"
);

DEFUN(gap_ctl_route_view,
	gap_ctl_route_view_cmd,
	"show route",
	SHOW_STR
	"show route\n"
)
{
	struct gap_route *route;
	char *name = (argc > 0) ? argv[0] : NULL;

	SHOW_CMD_RUN();

	pthread_mutex_lock(&rt_lock);
	vty_out(vty, "name proto sip sport dip dport outif inif entryip inport effectime%s", VTY_NEWLINE);
	list_for_each_entry(route, &rt_head, n_list) {
		if (name == NULL || (name != NULL && strcmp(route->name, name) == 0)) {
			vty_out(vty, "%s %s %s %s %s %s %s %s %s %s ", route->name, route->proto, route->sip, route->sport, route->dip, route->dport, route->outif, route->inif, route->entryip, route->inport);
			if (route->effectime[0] == '\0')
				vty_out(vty, "*%s", VTY_NEWLINE);
			else
				vty_out(vty, "%s%s", route->effectime, VTY_NEWLINE);
		}
	}
	pthread_mutex_unlock(&rt_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_route_view,
	gap_ctl_route_view_o_cmd,
	"show outer route",
	SHOW_STR
	"outer machine\n"
	"show route\n"
);


ALIAS(gap_ctl_route_view,
	gap_ctl_route_view_byname_cmd,
	"show route NAME",
	SHOW_STR
	"show route\n"
	"name\n"
);

ALIAS(gap_ctl_route_view,
	gap_ctl_route_view_byname_o_cmd,
	"show outer route NAME",
	SHOW_STR
	"outer machine\n"
	"show route\n"
	"name\n"
);

int gap_cmd_impl_route_add(struct vty *vty, char *name, char *proto, char *sip, char *sport, char *dip, char *dport, char *outif, char *inif, char *entryip, char *inport, char *etime)
{
	struct interface *ifp;
	struct gap_route *gr, *route, *ret = NULL;
	struct gap_ipgroup *sipgroup = NULL;
	struct gap_ipgroup *dipgroup = NULL;
	char *iphy = NULL;

	/* check dependent */
	if (NULL == (sipgroup = check_ipgroup_created(sip))) 
	{
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* check dependent */
	if (NULL == (dipgroup = check_ipgroup_created(dip))) 
	{
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* check ipgroup invalid */
	if (check_ipgroup_invalid(dip, inport)) 
	{
		vty_result(ERR_CODE_NOMATCH, ERR_CODE_NOMATCH_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	if (NULL == (ifp = if_get_by_name(inif))) 
	{
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	route = SCMalloc(sizeof(struct gap_route));
	if (NULL == route) 
	{
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	memset(route, 0, sizeof(struct gap_route));
	strncpy(route->name, name, sizeof(route->name) - 1);
	strncpy(route->proto, proto, sizeof(route->proto) - 1);
	strncpy(route->sip, sip, sizeof(route->sip) - 1);
	strncpy(route->sport, sport, sizeof(route->sport) - 1);
	strncpy(route->dip, dip, sizeof(route->dip) - 1);
	strncpy(route->dport, dport, sizeof(route->dport) - 1);
	strncpy(route->outif, outif, sizeof(route->outif) - 1);
	strncpy(route->inif, inif, sizeof(route->inif) - 1);
	strncpy(route->entryip, entryip ? entryip : "", sizeof(route->entryip) - 1);
	strncpy(route->inport, inport, sizeof(route->inport) - 1);
	if (etime != NULL) 
	{
		urldecode(etime);
		strncpy(route->effectime, etime, sizeof(route->effectime) - 1);
		timemgr_get(&route->tacl, route->effectime);
	}
	route->sip_group = sipgroup;
	route->dip_group = dipgroup;

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(gr, &rt_head, n_list) 
	{
		if (0 == strcmp(gr->name, name)) 
		{
			/* HIT */
			ret = gr;
			break;
		}
	}

	if (NULL == ret) 
	{
		if (rfun[op_add])
		{
			/* Callback route function */
			if (rfun[op_add](NULL, route)) {
				pthread_mutex_unlock(&rt_lock);
				SCFree(route);
				vty_result(ERR_CODE_CALLBACKERR, ERR_CODE_CALLBACKERR_DESC);
				return CMD_ERR_NOTHING_TODO;
			}

		}
		list_add(&route->n_list, &rt_head);
		rt_count++;
	}
	else 
	{
		SCFree(route);
	}
	pthread_mutex_unlock(&rt_lock);

	if (ret) 
	{
		vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	
	/***********************************************************************************************************/

	int nIndex = 0;
	int chInterfaceArray[INTERFACE_NUM] = { 0 };

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(route, &rt_head, n_list) 
	{
		if (RUN_AS_INNER())
		{
			nIndex = atoi(&route->inif[3]);				
		}
		else
		{
			nIndex = atoi(&route->outif[3]);
		}

		if( (nIndex >= 0) && (nIndex < INTERFACE_NUM) );
		{
			chInterfaceArray[nIndex] = 1;
		}
		
	}
	pthread_mutex_unlock(&rt_lock);

	FILE* hFile = fopen("/etc/gap/businessinif.conf", "w+");
	if (hFile != NULL)
	{
		char chData[10] = { 0 };
		for (nIndex = 0; nIndex < INTERFACE_NUM; nIndex++)
		{
			if (chInterfaceArray[nIndex] == 1)
			{
				snprintf(chData, sizeof(chData), "eth%d\r\n", nIndex);
				fwrite(chData, sizeof(char), strlen(chData), hFile);
			}
		}
		
		fclose(hFile);
	}

	return CMD_SUCCESS;
}

int gap_cmd_impl_route_edit(struct vty *vty, char *name, char *proto, char *sip, char *sport, char *dip, char *dport, char *outif, char *inif, char *entryip, char *inport, char *etime)
{
	char *iphy = NULL;
	struct interface *ifp;
	struct gap_ipgroup *sipgroup = NULL;
	struct gap_ipgroup *dipgroup = NULL;
	struct gap_route oldroute, *route, *ret = NULL;

	/* check dependent */
	if (NULL == (sipgroup = check_ipgroup_created(sip))) {
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* check dependent */
	if (NULL == (dipgroup = check_ipgroup_created(dip))) {
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* check ipgroup invalid */
	if (check_ipgroup_invalid(dip, inport)) {
		vty_result(ERR_CODE_NOMATCH, ERR_CODE_NOMATCH_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	if (NULL == (ifp = if_lookup_by_name(inif))) {
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(route, &rt_head, n_list) {
		if (0 == strcmp(route->name, name)) {
			/* HIT */
			memcpy(&oldroute, route, sizeof(oldroute));
			strncpy(route->proto, proto, sizeof(route->proto) - 1);
			strncpy(route->sip, sip, sizeof(route->sip) - 1);
			strncpy(route->sport, sport, sizeof(route->sport) - 1);;
			strncpy(route->dip, dip, sizeof(route->dip) - 1);
			strncpy(route->dport, dport, sizeof(route->dport) - 1);
			strncpy(route->outif, outif, sizeof(route->outif) - 1);
			strncpy(route->inif, inif, sizeof(route->inif) - 1);
			strncpy(route->entryip, entryip ? entryip : "", sizeof(route->entryip) - 1);
			strncpy(route->inport, inport, sizeof(route->inport) - 1);
			timemgr_put(&route->tacl);/* Release reference count */
			memset(route->effectime, 0, sizeof(route->effectime));
			memset(&route->tacl, 0, sizeof(route->tacl));
			if (etime != NULL) {
				urldecode(etime);
				strncpy(route->effectime, etime, sizeof(route->effectime) - 1);
				timemgr_get(&route->tacl, route->effectime);
			}
			route->sip_group = sipgroup;
			route->dip_group = dipgroup;
			ret = route;
			break;
		}
	}
	pthread_mutex_unlock(&rt_lock);

	/* object not found */
	if (NULL == ret) {
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* Callback route function */
	if (rfun[op_edit]) {
		if (rfun[op_edit](&oldroute, ret)) {
			vty_result(ERR_CODE_CALLBACKERR, ERR_CODE_CALLBACKERR_DESC);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_route_edit,
	gap_ctl_route_edit_cmd,
	"route edit routename WORD proto PROTOCOL sip WORD sport WORD dip WORD dport WORD outif INTERFACE inif INTERFACE entryip A.B.C.D inport <0-65535> {effectime WORD}",
	"route command\n"
	"edit route\n"
	"routename\n"
	"name of route\n"
	"protocol\n"
	"PROTOCOL, such as: FTP,HTTP,TDCS\n"
	"source ip\n"
	"name of ipgroup\n"
	"source port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"destination ip\n"
	"name of ipgroup\n"
	"destination port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"outcoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"incoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"entry ip\n"
	"entry ip, such as A.B.C.D\n"
	"incoming port\n"
	"0-65535\n"
	"Effective time\n"
	"name of timerange and timegroup, such as:time1, timeg1(g)\n")
{
	char *name, *proto, *sip, *sport, *dip, *dport, *outif, *inif, *entryip, *inport, *etime;
	name = argv[0];
	proto = argv[1];
	sip = argv[2];
	sport = argv[3];
	dip = argv[4];
	dport = argv[5];
	outif = argv[6];
	inif = argv[7];
	entryip = argv[8];
	inport = argv[9];
	etime = argv[10];
	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();
	return gap_cmd_impl_route_edit(vty, name, proto, sip, sport, dip, dport, outif, inif, entryip, inport, etime);
}

ALIAS(gap_ctl_route_edit,
	gap_ctl_route_edit_o_cmd,
	"outer route edit routename WORD proto PROTOCOL sip WORD sport WORD dip WORD dport WORD outif INTERFACE inif INTERFACE entryip A.B.C.D inport <0-65535> {effectime WORD}",
	"outer machine\n"
	"route command\n"
	"edit route\n"
	"routename\n"
	"name of route\n"
	"protocol\n"
	"PROTOCOL, such as: FTP,HTTP,TDCS\n"
	"source ip\n"
	"name of ipgroup\n"
	"source port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"destination ip\n"
	"name of ipgroup\n"
	"destination port\n"
	"port(such as:80 or 9000;9002;9005)\n"
	"outcoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"incoming interface\n"
	"INTERFACE, such as:(P0|P1|P2|P3|P4|P5)\n"
	"entry ip\n"
	"entry ip, such as A.B.C.D\n"
	"incoming port\n"
	"0-65535\n"
	"Effective time\n"
	"name of timerange and timegroup, such as:time1, timeg1(g)\n");

void register_rfun(int type, route_fun fun)
{
	if (type >= op_max)
		return;

	//pthread_mutex_lock(&misc_lock);
	rfun[type] = fun;
	//pthread_mutex_unlock(&misc_lock);
}

void ipgroup_lock(void)
{
	pthread_mutex_lock(&rt_lock);
}

void ipgroup_unlock(void)
{
	pthread_mutex_unlock(&rt_lock);
}

int route_config_write(struct vty *vty)
{
	struct gap_ipgroup *ipgroup;
	struct gap_route *route;
	struct gap_rt *rt;

	pthread_mutex_lock(&rt_lock);
	list_for_each_entry(ipgroup, &ipgroup_head, n_list) {
		vty_out(vty, "ipgroup add name %s ipset %s level %d%s", ipgroup->name, ipgroup->ipset, ipgroup->level, VTY_NEWLINE);
	}

	list_for_each_entry(route, &rt_head, n_list) {
		struct interface *ifp = if_lookup_by_name(route->inif);
		if (ifp == NULL)
			continue;
		vty_out(vty, "route add routename %s proto %s sip %s sport %s dip %s dport %s outif %s inif %s ",
			route->name, route->proto, route->sip, route->sport, route->dip, route->dport, route->outif, ifp->name);

		if (strlen(route->entryip))
			vty_out(vty, "entryip %s ", route->entryip);

		vty_out(vty, "inport %s ", route->inport);

		if (strlen(route->effectime))
			vty_out(vty, "effectime %s ", route->effectime);

		vty_out(vty, "%s", VTY_NEWLINE);
	}

	pthread_mutex_unlock(&rt_lock);

	return 0;
}

void route_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_route_add_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_route_edit_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_route_del_o_cmd);

	install_element(CONFIG_NODE, &gap_ctl_ipgroup_add_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipgroup_edit_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipgroup_del_o_cmd);

	install_element(CONFIG_NODE, &gap_ctl_route_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_route_edit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_route_del_cmd);

	install_element(CONFIG_NODE, &gap_ctl_ipgroup_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipgroup_edit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipgroup_del_cmd);
}

void route_show_cmd_init(unsigned int machine)
{
	if (machine == inner_machine || machine == outer_machine) {
		install_element(VIEW_NODE, &gap_ctl_route_view_cmd);
		install_element(VIEW_NODE, &gap_ctl_route_view_o_cmd);
		install_element(VIEW_NODE, &gap_ctl_route_view_byname_cmd);
		install_element(VIEW_NODE, &gap_ctl_route_view_byname_o_cmd);
		install_element(VIEW_NODE, &gap_ctl_ipgroup_view_cmd);
		install_element(VIEW_NODE, &gap_ctl_ipgroup_view_o_cmd);

		install_element(ENABLE_NODE, &gap_ctl_route_view_cmd);
		install_element(ENABLE_NODE, &gap_ctl_route_view_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_route_view_byname_cmd);
		install_element(ENABLE_NODE, &gap_ctl_route_view_byname_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_ipgroup_view_cmd);
		install_element(ENABLE_NODE, &gap_ctl_ipgroup_view_o_cmd);
	}
}

void route_init(void)
{
	pthread_mutex_init(&rt_lock, NULL);
	INIT_LIST_HEAD(&rt_head);
	INIT_LIST_HEAD(&ipgroup_head);
}

void route_exit(void)
{
	do {
		struct gap_ipgroup *ipgroup, *next;
		pthread_mutex_lock(&rt_lock);
		list_for_each_entry_safe(ipgroup, next, &ipgroup_head, n_list) {
			list_del(&ipgroup->n_list);
			SCFree(ipgroup);
		}
		pthread_mutex_unlock(&rt_lock);
	} while (0);

	do {
		struct gap_route *route, *next;
		pthread_mutex_lock(&rt_lock);
		//???????	  
		list_for_each_entry_safe(route, next, &rt_head, n_list) {
			if (rfun[op_del]) {
				/* Callback route function */
				if (rfun[op_del](route, NULL)) {
					SCLogInfo("Callback route function failed.");
				}
			}
			list_del(&route->n_list);
			SCFree(route);
			rt_count--;
		}
		pthread_mutex_unlock(&rt_lock);
	} while (0);
}

