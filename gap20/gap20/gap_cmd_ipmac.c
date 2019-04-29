
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
#include "vtysh/vtysh.h"
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
#include "gap_cmd_ipmac.h"

/*
 *	Hash table: for ip-mac lookups
 */
#define GAP_IPMAC_TAB_BITS 7
#define GAP_IPMAC_TAB_SIZE (1 << GAP_IPMAC_TAB_BITS)
#define GAP_IPMAC_TAB_MASK (GAP_IPMAC_TAB_SIZE - 1)

static struct list_head ipmac_table[GAP_IPMAC_TAB_SIZE];
static struct list_head ipmac_list = LIST_HEAD_INIT(ipmac_list);
static pthread_rwlock_t ipmac_lock;
unsigned int ipmac_count = 0;

static inline unsigned ipmac_hashkey(unsigned int addr)
{
	unsigned short port = (unsigned short)addr;
	register unsigned porth = ntohs(port);

	return (ntohl(addr) ^ (porth >> GAP_IPMAC_TAB_BITS) ^ porth)
		& GAP_IPMAC_TAB_MASK;
}

DEFUN(gap_ctl_ipmac_add,
	gap_ctl_ipmac_add_cmd,
	"ipmac add device WORD ip A.B.C.D mac WORD action (b|w) enable (1|0)",
	"ipmac command\n"
	"add ipmac rule\n"
	"device\n"
	"device name\n"
	"ip\n"
	"ip address,eg:192.168.1.100\n"
	"mac\n"
	"mac address, eg:00:01:5a:7d:04:05\n"
	"action\n"
	"blocking\n"
	"warning\n"
	"enable state\n"
	"1:enable\n"
	"0:disable\n"
)
{
	unsigned int ip;
	unsigned char mac[6];
	struct gap_ipmac_rule *gir, *ipmac, *ret = NULL;
	unsigned hash;

	/* ÅäÖÃÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
	CONF_CMD_RUN();

	ip = inet_addr(argv[1]);
	imac_addr(argv[2], mac);

	ipmac = SCMalloc(sizeof(struct gap_ipmac_rule));
	if (NULL == ipmac) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	ipmac->ip = ip;
	memcpy(ipmac->mac, mac, sizeof(mac));
	strncpy(ipmac->device, argv[0], sizeof(ipmac->device) - 1);
	strncpy(ipmac->action, argv[3], sizeof(ipmac->action) - 1);
	ipmac->enable = atoi(argv[4]);

	hash = ipmac_hashkey(ip);
	pthread_rwlock_wrlock(&ipmac_lock);
	list_for_each_entry(gir, &ipmac_table[hash], n_list) {
		if (ipmac->ip == gir->ip) {
			/* HIT */
			ret = gir;
			break;
		}
	}

	if (NULL == ret) {
		ipmac_count++;
		list_add(&ipmac->n_list, &ipmac_table[hash]);
		list_add(&ipmac->l_list, &ipmac_list);
	}
	else {
		SCFree(ipmac);
	}
	pthread_rwlock_unlock(&ipmac_lock);

	if (ret) {
		vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipmac_add,
	gap_ctl_ipmac_add_o_cmd,
	"outer ipmac add device WORD ip A.B.C.D mac WORD action (b|w) enable (1|0)",
	"outer machine\n"
	"ipmac command\n"
	"add ipmac rule\n"
	"device\n"
	"device name\n"
	"ip\n"
	"ip address,eg:192.168.1.100\n"
	"mac\n"
	"mac address, eg:00:01:5a:7d:04:05\n"
	"action\n"
	"blocking\n"
	"warning\n"
	"enable state\n"
	"1:enable\n"
	"0:disable\n"
);

DEFUN(gap_ctl_ipmac_del,
	gap_ctl_ipmac_del_cmd,
	"ipmac delete ip A.B.C.D",
	"ipmac command\n"
	"delete ipmac rule\n"
	"ip\n"
	"ip address\n"
)
{
	struct gap_ipmac_rule *ipmac, *next;
	unsigned int hash, ip;
	int del = 0;

	/* ÅäÖÃÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
	CONF_CMD_RUN();

	ip = inet_addr(argv[0]);
	hash = ipmac_hashkey(ip);

	pthread_rwlock_wrlock(&ipmac_lock);
	list_for_each_entry_safe(ipmac, next, &ipmac_table[hash], n_list) {
		if (ip == ipmac->ip) {
			/* HIT */
			ipmac_count--;
			list_del(&ipmac->n_list);
			list_del(&ipmac->l_list);
			SCFree(ipmac);
			del = 1;
		}
	}
	pthread_rwlock_unlock(&ipmac_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipmac_del,
	gap_ctl_ipmac_del_o_cmd,
	"outer ipmac delete ip A.B.C.D",
	"outer machine\n"
	"ipmac command\n"
	"delete ipmac rule\n"
	"ip\n"
	"ip address\n"
);

DEFUN(gap_ctl_ipmac_view,
	gap_ctl_ipmac_view_cmd,
	"show ipmac {pgindex <0-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"show ipmac rule.(devicename ip mac action enable)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n"
)
{
	struct gap_ipmac_rule *ipmac;
	struct in_addr   inaddr;
	int idx;

	/* ²éÑ¯ÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
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

	pthread_rwlock_rdlock(&ipmac_lock);
	list_for_each_entry(ipmac, &ipmac_list, l_list) {
		if ((pgindex == 0) || (count >= ((pgindex - 1)*pgsize) && count < (pgindex*pgsize))) {
			inaddr.s_addr = ipmac->ip;
			vty_out(vty, "%s %s  "MAC_FMT" %s %d%s", ipmac->device, inet_ntoa(inaddr), MAC_ARG(ipmac->mac), ipmac->action, ipmac->enable, VTY_NEWLINE);
		}
		count++;
	}
	pthread_rwlock_unlock(&ipmac_lock);

	vty_out(vty, "[pageindex=%d,pagesize=%d,totalline=%d]%s", pgindex, pgsize, count, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipmac_view,
	gap_ctl_ipmac_view_o_cmd,
	"show outer ipmac {pgindex <0-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"outer machine\n"
	"show ipmac rule.(devicename ip mac action enable)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n");

DEFUN(gap_ctl_ipmac_edit,
	gap_ctl_ipmac_edit_cmd,
	"ipmac edit device WORD ip A.B.C.D mac WORD action (b|w) enable (1|0)",
	"ipmac command\n"
	"edit ipmac rule\n"
	"device\n"
	"device name\n"
	"ip\n"
	"ip address,eg:192.168.1.100\n"
	"mac\n"
	"mac address, eg:00:01:5a:7d:04:05\n"
	"action\n"
	"blocking\n"
	"warning\n"
	"enable state\n"
	"1:enable\n"
	"0:disable\n"
)
{
	unsigned int ip;
	unsigned char mac[6];
	struct gap_ipmac_rule *gir, *ret = NULL;
	unsigned hash;

	/* ÅäÖÃÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
	CONF_CMD_RUN();

	ip = inet_addr(argv[1]);
	imac_addr(argv[2], mac);

	hash = ipmac_hashkey(ip);
	pthread_rwlock_wrlock(&ipmac_lock);
	list_for_each_entry(gir, &ipmac_table[hash], n_list) {
		if (ip == gir->ip) {
			/* HIT */
			strncpy(gir->device, argv[0], sizeof(gir->device) - 1);
			memcpy(gir->mac, mac, sizeof(mac));
			strncpy(gir->action, argv[3], sizeof(gir->action) - 1);
			gir->enable = atoi(argv[4]);
			ret = gir;
			break;
		}
	}
	pthread_rwlock_unlock(&ipmac_lock);

	if (NULL == ret) {
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ipmac_edit,
	gap_ctl_ipmac_edit_o_cmd,
	"outer ipmac edit device WORD ip A.B.C.D mac WORD action (b|w) enable (1|0)",
	"outer machine\n"
	"ipmac command\n"
	"edit ipmac rule\n"
	"device\n"
	"device name\n"
	"ip\n"
	"ip address,eg:192.168.1.100\n"
	"mac\n"
	"mac address, eg:00:01:5a:7d:04:05\n"
	"action\n"
	"blocking\n"
	"warning\n"
	"enable state\n"
	"1:enable\n"
	"0:disable\n"
);

int check_ipmac(unsigned int ip, unsigned char *mac, char rule[], int len)
{
	struct gap_ipmac_rule *gir;
	unsigned hash;
	int ret = 0;
	char m[6];
	memset(m, 0, sizeof(m));

	/* Not ssl */
	if (0 == memcmp(mac, m, sizeof(m))) {
		return 0;
	}

	hash = ipmac_hashkey(ip);
	pthread_rwlock_rdlock(&ipmac_lock);
	list_for_each_entry(gir, &ipmac_table[hash], n_list) {
		if (ip == gir->ip) {
			/* HIT */
			if (gir->enable == 0)
				break;

			if (0 != memcmp(mac, gir->mac, sizeof(gir->mac))) {
				struct in_addr   inaddr;
				inaddr.s_addr = gir->ip;
				snprintf(rule, len, "ipmac:%s-"MAC_FMT, inet_ntoa(inaddr), MAC_ARG(gir->mac));
				if (0 == strncmp(gir->action, "b", sizeof(gir->action))) {
					SCLogInfo("ip-mac no match.");
					ret = -1;
				}
				else {
					SCLogInfo("ip-mac no match.");
					ret = -2;
				}
			}
			break;
		}
	}
	pthread_rwlock_unlock(&ipmac_lock);

	return ret;
}

int ipmac_config_write(struct vty *vty)
{
	struct gap_ipmac_rule *ipmac;
	struct in_addr   inaddr;
	int idx;
	pthread_rwlock_rdlock(&ipmac_lock);
	/* find the whole hash table */
	for (idx = 0; idx < GAP_IPMAC_TAB_SIZE; idx++) {
		list_for_each_entry(ipmac, &ipmac_table[idx], n_list) {
			inaddr.s_addr = ipmac->ip;
			vty_out(vty, "ipmac add device %s ip %s mac "MAC_FMT" action %s enable %d%s", ipmac->device, inet_ntoa(inaddr), MAC_ARG(ipmac->mac), ipmac->action, ipmac->enable, VTY_NEWLINE);
		}
	}
	pthread_rwlock_unlock(&ipmac_lock);
	return 0;
}

void ipmac_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_ipmac_edit_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipmac_add_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipmac_del_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipmac_edit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipmac_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ipmac_del_cmd);
}

void ipmac_show_cmd_init(unsigned int machine)
{
	if (machine == outer_machine || machine == inner_machine) {
		install_element(VIEW_NODE, &gap_ctl_ipmac_view_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_ipmac_view_o_cmd);
	}

	install_element(VIEW_NODE, &gap_ctl_ipmac_view_cmd);
	install_element(ENABLE_NODE, &gap_ctl_ipmac_view_cmd);
}

void ipmac_init(void)
{
	int idx;
	pthread_rwlock_init(&ipmac_lock, NULL);
	for (idx = 0; idx < GAP_IPMAC_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&ipmac_table[idx]);
	}
}

void ipmac_exit(void)
{
	struct gap_ipmac_rule *ipmac, *next;
	int idx;
	pthread_rwlock_wrlock(&ipmac_lock);
	for (idx = 0; idx < GAP_IPMAC_TAB_SIZE; idx++) {
		list_for_each_entry_safe(ipmac, next, &ipmac_table[idx], n_list) {
			ipmac_count--;
			list_del(&ipmac->n_list);
			list_del(&ipmac->l_list);
			SCFree(ipmac);
		}
	}
	pthread_rwlock_unlock(&ipmac_lock);
}

