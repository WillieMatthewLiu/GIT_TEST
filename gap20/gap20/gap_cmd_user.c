
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
#include "gap_cmd_user.h"
#include "gap_stgy.h"


/*
 *	Hash table: for user lookups
 */
struct list_head user_table[GAP_USER_TAB_SIZE];
static struct list_head user_list = LIST_HEAD_INIT(user_list);
pthread_rwlock_t user_lock;
unsigned int user_count = 0;

static int translate_portset(char *portset, struct port_range pr[], int *num)
{
	int n = 0;
	*num = 0;
	char *token, *p, *second, *out_ptr = NULL, old;
	char ports[1024], *pt = ports;
	strncpy(ports, portset, sizeof(ports) - 1);
	while ((p = strtok_r(pt, ";,", &out_ptr)) != NULL)
	{
		if (n >= PORT_NUM) {
			SCLogInfo("Port num overload.");
			return -1;
		}

		pt = NULL;
		if (NULL != (token = strchr(p, '-'))) {
			old = *token;
			*token = '\0';
			second = token + 1;
			pr[n].first_port = atoi(p);
			pr[n].second_port = atoi(second);
			pr[n].type = 2;
		}
		else {
			pr[n].first_port = atoi(p);
			pr[n].second_port = pr[n].first_port;
			pr[n].type = 1;
		}
		n++;
	}

	*num = n;
	return 0;
}

/*非加密卡用户，检查IP的唯一性*/
static int check_ip_conflict(const char *username, const char *ips)
{
	unsigned int first_ip;
	unsigned int second_ip;
	char strip[USER_IP_LEN + 1];
	strncpy(strip, ips, sizeof(strip) - 1);
	char *token = strchr(strip, '-');
	if (token) {
		*token = '\0';
		first_ip = inet_addr(strip);
		second_ip = inet_addr(token + 1);
		*token = '-';
	}
	else {
		first_ip = inet_addr(strip);
		second_ip = first_ip;
	}

	struct gap_user_rule *user;
	pthread_rwlock_rdlock(&user_lock);
	list_for_each_entry(user, &user_list, l_list) {
		if (0 == user->type && 0 != strcmp(username, user->username)) {
			if (((first_ip >= user->first_ip) && (first_ip <= user->second_ip))
				|| ((user->first_ip >= first_ip) && (user->first_ip <= second_ip))) {
				pthread_rwlock_unlock(&user_lock);
				return 1;
			}
		}
	}
	pthread_rwlock_unlock(&user_lock);
	return 0;
}

unsigned user_hashkey(const char *name)
{
	return GAP_USER_TAB_MASK & jhash(name, strlen(name), 0);
}

DEFUN(gap_ctl_user_add,
	gap_ctl_user_add_cmd,
	"user add username WORD groupname WORD ip WORD port WORD mac WORD level (0|1|2|3) enable (0|1) type (0|1)",
	"user command\n"
	"add user rule.\n"
	"username\n"
	"name of user\n"
	"groupname\n"
	"name of group\n"
	"ip\n"
	"ip address,such as:192.168.1.1 or 192.168.8.1-192.168.8.10\n"
	"port\n"
	"port address, suce as:80,8080,9090\n"
	"mac\n"
	"mac address\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
	"enable state\n"
	"0:disable\n"
	"1:enable\n"
	"type\n"
	"0:no ssl\n"
	"1:ssl\n"
)
{
	unsigned char mac[6];
	struct gap_user_rule *gur, *user, *ret = NULL;
	unsigned hash;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	/* 检查唯一性 */
	if (atoi(argv[7]) == 0 && check_ip_conflict(argv[0], argv[2])) {
		vty_result(ERR_CODE_CONFLICT, ERR_CODE_CONFLICT_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	imac_addr(argv[4], mac);
	/* check dependent */
	struct gap_group_rule* group = get_group_by_name(argv[1]);
	if (group == NULL) {
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	user = SCMalloc(sizeof(struct gap_user_rule));
	if (NULL == user) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	memset(user, 0, sizeof(struct gap_user_rule));

	user->group = group;
	strncpy(user->strip, argv[2], sizeof(user->strip) - 1);
	char *token = strchr(user->strip, '-');
	if (token) {
		*token = '\0';
		user->first_ip = inet_addr(user->strip);
		user->second_ip = inet_addr(token + 1);
		*token = '-';
	}
	else {
		user->first_ip = inet_addr(user->strip);
		user->second_ip = user->first_ip;
	}
	user->level = atoi(argv[5]);
	user->enable = atoi(argv[6]);
	user->type = atoi(argv[7]);
	memcpy(user->mac, mac, sizeof(mac));
	strncpy(user->username, argv[0], sizeof(user->username) - 1);
	strncpy(user->port, argv[3], sizeof(user->port) - 1);
	translate_portset(argv[3], user->pt, &user->pt_num);
	hash = user_hashkey(user->username);
	pthread_rwlock_wrlock(&user_lock);
	list_for_each_entry(gur, &user_table[hash], n_list) {
		if (0 == strcmp(gur->username, user->username)) {
			/* HIT */
			ret = gur;
			break;
		}
	}

	if (NULL == ret) {
		user_count++;
		list_add(&user->n_list, &user_table[hash]);
		list_add(&user->g_list, &group->user_list);
		list_add(&user->l_list, &user_list);
	}
	else {
		SCFree(user);
	}
	pthread_rwlock_unlock(&user_lock);

	if (ret) {
		vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_user_add,
	gap_ctl_user_add_o_cmd,
	"outer user add username WORD groupname WORD ip WORD port WORD mac WORD level (0|1|2|3) enable (0|1) type (0|1)",
	"outer machine\n"
	"user command\n"
	"add user rule.\n"
	"username\n"
	"name of user\n"
	"groupname\n"
	"name of group\n"
	"ip\n"
	"ip address,such as:192.168.1.1 or 192.168.8.1-192.168.8.10\n"
	"port\n"
	"port address, suce as:80,8080,9090\n"
	"mac\n"
	"mac address\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
	"enable state\n"
	"0:disable\n"
	"1:enable\n"
	"type\n"
	"0:no ssl\n"
	"1:ssl\n"
);

DEFUN(gap_ctl_user_del,
	gap_ctl_user_del_cmd,
	"user delete username WORD",
	"user command\n"
	"delete user rule.\n"
	"username\n"
	"name of user\n"
)
{
	struct gap_user_rule *user, *next;
	unsigned hash;
	int del = 0;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	hash = user_hashkey(argv[0]);
	pthread_rwlock_wrlock(&user_lock);
	list_for_each_entry_safe(user, next, &user_table[hash], n_list) {
		if (0 == strcmp(argv[0], user->username)) {
			/* HIT */
			user_count--;
			list_del(&user->n_list);
			list_del(&user->g_list);
			list_del(&user->l_list);
			SCFree(user);
			del = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&user_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_user_del,
	gap_ctl_user_del_o_cmd,
	"outer user delete username WORD",
	"outer machine\n"
	"user command\n"
	"delete user rule.\n"
	"username\n"
	"name of user\n"
);

DEFUN(gap_ctl_user_view,
	gap_ctl_user_view_cmd,
	"show user {pgindex <0-2147483647>|pgsize <1-2147483647> |name NAME}",
	SHOW_STR
	"show user rule.(username groupname ip mac enable type)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n"
	"name\n"
	"username\n"
)
{
	struct gap_user_rule *user;
	int idx;
	/* 查询命令是否远端执行 */
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

	pthread_rwlock_rdlock(&user_lock);
	list_for_each_entry(user, &user_list, l_list) {
		if (argv[2] != NULL) {
			if (0 == strcmp(argv[2], user->username)) {
				vty_out(vty, "%s  %s  %s  %s "MAC_FMT"  %d  %d  %d%s", user->username, user->group->groupname, user->strip, user->port, MAC_ARG(user->mac), user->level, user->enable, user->type, VTY_NEWLINE);
				pthread_rwlock_unlock(&user_lock);
				return CMD_SUCCESS;
			}
		}
		else {
			if ((pgindex == 0) || (count >= ((pgindex - 1)*pgsize) && count < (pgindex*pgsize))) {
				vty_out(vty, "%s  %s  %s  %s "MAC_FMT"  %d  %d  %d%s", user->username, user->group->groupname, user->strip, user->port, MAC_ARG(user->mac), user->level, user->enable, user->type, VTY_NEWLINE);
			}
			count++;
		}
	}
	pthread_rwlock_unlock(&user_lock);

	vty_out(vty, "[pageindex=%d,pagesize=%d,totalline=%d]%s", pgindex, pgsize, count, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_user_view,
	gap_ctl_user_view_o_cmd,
	"show outer user {pgindex <0-2147483647>|pgsize <1-2147483647>|name NAME}",
	SHOW_STR
	"outer machine\n"
	"view user rule.(username groupname ip mac enable type)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n"
	"name\n"
	"username\n");

DEFUN(gap_ctl_user_edit,
	gap_ctl_user_edit_cmd,
	"user edit username WORD groupname WORD ip WORD port WORD mac WORD level (0|1|2|3) enable (0|1) type (0|1)",
	"user command\n"
	"edit user rule.\n"
	"username\n"
	"name of user\n"
	"groupname\n"
	"name of group\n"
	"ip\n"
	"ip address,such as:192.168.1.1 or 192.168.8.1-192.168.8.10\n"
	"port\n"
	"port address, suce as:80,8080,9090\n"
	"mac\n"
	"mac address\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
	"enable state\n"
	"0:disable\n"
	"1:enable\n"
	"type\n"
	"0:no ssl\n"
	"1:ssl\n"
)
{
	unsigned char mac[6];
	struct gap_user_rule *gur, *ret = NULL;
	unsigned hash;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	/* 检查唯一性 */
	if (atoi(argv[7]) == 0 && check_ip_conflict(argv[0], argv[2])) {
		vty_result(ERR_CODE_CONFLICT, ERR_CODE_CONFLICT_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* check dependent */
	struct gap_group_rule* group = get_group_by_name(argv[1]);
	if (group == NULL) {
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	imac_addr(argv[4], mac);

	hash = user_hashkey(argv[0]);
	pthread_rwlock_wrlock(&user_lock);
	list_for_each_entry(gur, &user_table[hash], n_list) {
		if (0 == strcmp(gur->username, argv[0])) {
			/* HIT */
			list_del(&gur->g_list);/*从用户组脱链*/
			list_add(&gur->g_list, &group->user_list);/*加入新用户组*/
			gur->group = group;
			strncpy(gur->strip, argv[2], sizeof(gur->strip) - 1);
			char *token = strchr(gur->strip, '-');
			if (token) {
				*token = '\0';
				gur->first_ip = inet_addr(gur->strip);
				gur->second_ip = inet_addr(token + 1);
				*token = '-';
			}
			else {
				gur->first_ip = inet_addr(gur->strip);
				gur->second_ip = gur->first_ip;
			}
			gur->level = atoi(argv[5]);
			gur->enable = atoi(argv[6]);
			gur->type = atoi(argv[7]);
			memcpy(gur->mac, mac, sizeof(mac));
			strncpy(gur->port, argv[3], sizeof(gur->port) - 1);
			translate_portset(argv[3], gur->pt, &gur->pt_num);
			ret = gur;
			break;
		}
	}
	pthread_rwlock_unlock(&user_lock);

	if (NULL == ret) {
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_user_edit,
	gap_ctl_user_edit_o_cmd,
	"outer user edit username WORD groupname WORD ip WORD port WORD mac WORD level (0|1|2|3) enable (0|1) type (0|1)",
	"outer machine\n"
	"user command\n"
	"edit user rule.\n"
	"username\n"
	"name of user\n"
	"groupname\n"
	"name of group\n"
	"ip\n"
	"ip address,such as:192.168.1.1 or 192.168.8.1-192.168.8.10\n"
	"port\n"
	"port address, suce as:80,8080,9090\n"
	"mac\n"
	"mac address\n"
	"the level of user\n"
	"0: Top Secret\n"
	"1: Secret\n"
	"2: Confidential\n"
	"3: Unclassified\n"
	"enable state\n"
	"0:disable\n"
	"1:enable\n"
	"type\n"
	"0:no ssl\n"
	"1:ssl\n"
);

int check_user_privilege(struct acl_data* ad, struct gap_group_rule** group, char rule[], int len)
{
	struct gap_user_rule* user;
	unsigned hash;
	int ret = 0;
	char mac_null[6] = { 0,0,0,0,0,0 };
	int user_level = -1;
	memset(rule, 0, len);

	/* No ssl card */
	if( (0 == strcmp(ad->user, "none"))  || (ad->svrid == SVR_ID_FTPDATA) )
	{
		struct gap_user_rule* user;
		int idx;
		ret = -1;
		snprintf(rule, len, "user:Not Found");
		pthread_rwlock_wrlock(&user_lock);
		for (idx = 0; idx < GAP_USER_TAB_SIZE; idx++) 
		{
			list_for_each_entry(user, &user_table[idx], n_list) 
			{
				if (user->type == 1)
				{
					continue;
				}					

				/* IP????? */
				if (user->first_ip != 0 && ad->sip >= user->first_ip && ad->sip <= user->second_ip) 
				{
					ret = 0;
					/* check Mac address */
					if ((0 != memcmp(mac_null, user->mac, sizeof(mac_null))) && (0 != memcmp(user->mac, ad->smac, sizeof(user->mac)))) 
					{
						ret = -1;
						snprintf(rule, len, "user:%s", user->username);
						SCLogInfo("Mac err.");
						goto out;
					}

					/* check Port address */
					if (user->pt[0].first_port != 0) 
					{
						int i, sign = 0;
						for (i = 0; i < user->pt_num; i++) 
						{
							if (ad->sport >= user->pt[i].first_port && ad->sport <= user->pt[i].second_port) {
								sign = 1;
								break;
							}
						}
						if (sign == 0) 
						{
							ret = -1;
							snprintf(rule, len, "user:%s", user->username);
							SCLogInfo("Port err.");
							goto out;
						}
					}

					/* user is disable */
					if (0 == user->enable) 
					{
						snprintf(rule, len, "user:%s", user->username);
						SCLogInfo("User is disable.");
						ret = -1;
						goto out;
					}

					user_level = user->level;/* Get level for next check */
					*group = user->group;/* Get goupfor next check */
					strncpy(ad->user, user->username, sizeof(ad->user) - 1);/*Get username for http-rule*/
					snprintf(rule, len, "user:%s", user->username);/* Get user rule for log */
					goto out;
				}

				/* MAC????? */
				if ((0 != memcmp(mac_null, user->mac, sizeof(mac_null))) && (0 == memcmp(user->mac, ad->smac, sizeof(user->mac)))) 
				{
					ret = 0;
					/* check IP address */
					if (user->first_ip != 0)
					{
						SCLogInfo("Ip err.");
						snprintf(rule, len, "user:%s", user->username);
						ret = -1;
						goto out;
					}

					/* check Port address */
					if (user->pt[0].first_port != 0)
					{
						int i, sign = 0;
						for (i = 0; i < user->pt_num; i++)
						{
							if (ad->sport >= user->pt[i].first_port && ad->sport <= user->pt[i].second_port) {
								sign = 1;
								break;
							}
						}
						if (sign == 0) 
						{
							ret = -1;
							snprintf(rule, len, "user:%s", user->username);
							SCLogInfo("Port err.");
							goto out;
						}
					}

					/* user is disable */
					if (0 == user->enable)
					{
						SCLogInfo("User is disable.");
						snprintf(rule, len, "user:%s", user->username);
						ret = -1;
						goto out;
					}

					user_level = user->level;/* Get level for next check */
					*group = user->group;/* Get goupfor next check */
					strncpy(ad->user, user->username, sizeof(ad->user) - 1);/*Get username for http-rule*/
					snprintf(rule, len, "user:%s", user->username);/* Get user rule for log */
					goto out;
				}
			}
		}
	out:
		pthread_rwlock_unlock(&user_lock);
	}
	else 
	{
		hash = user_hashkey(ad->user);
		pthread_rwlock_rdlock(&user_lock);
		list_for_each_entry(user, &user_table[hash], n_list) 
		{
			if (user->type == 0)
			{
				continue;
			}				

			if (0 == strcmp(ad->user, user->username))
			{
				user_level = user->level;/* Get level for next check */
				*group = user->group;/* Get goupfor next check */
				snprintf(rule, len, "user:%s", user->username);/* Get user rule for log */

				/* user is disable */
				if (0 == user->enable) 
				{
					ret = -1;
					SCLogInfo("User is disable.");
					break;
				}

				/* check IP address */
				if (0 != user->first_ip && (ad->sip<user->first_ip || ad->sip>user->second_ip)) 
				{
					ret = -1;
					SCLogInfo("Ip err.");
					break;
				}

				/* check Mac address */
				if ((0 != memcmp(mac_null, user->mac, sizeof(mac_null))) && (0 != memcmp(user->mac, ad->smac, sizeof(user->mac)))) {
					ret = -1;
					SCLogInfo("Mac err.");
					break;
				}

				/* check Port address */
				if (user->pt[0].first_port != 0) {
					int i, sign = 0;
					for (i = 0; i < user->pt_num; i++) {
						if (ad->sport >= user->pt[i].first_port && ad->sport <= user->pt[i].second_port) {
							sign = 1;
							break;
						}
					}
					if (sign == 0) {
						ret = -1;
						SCLogInfo("Port err.");
					}
				}
				break;
			}
		}
		pthread_rwlock_unlock(&user_lock);
	}

	/* user privilege invalid */
	if (ret)
	{
		SCLogInfo("%s.", rule);
		return ret;
	}

	/* check level */
	if (user_level == -1) 
	{
		if (ad->src_level > ad->dst_level) 
		{
			snprintf(rule + strlen(rule), len - strlen(rule), " Level lower.");
			SCLogInfo("Level lower.");
			return -1;
		}
	}
	else 
	{
		if (ad->svrid != SVR_ID_FTPDATA)
		{
			ad->src_level = user_level;
		}
		
		if (ad->src_level > ad->dst_level) 
		{
			snprintf(rule + strlen(rule), len - strlen(rule), " Level lower.");
			SCLogInfo("Level lower.");
			return -1;
		}
	}
	
	return ret;
}

int user_config_write(struct vty *vty)
{
	struct gap_user_rule *user;
	int idx;

	pthread_rwlock_rdlock(&user_lock);
	for (idx = 0; idx < GAP_USER_TAB_SIZE; idx++) {
		list_for_each_entry(user, &user_table[idx], n_list) {
			vty_out(vty, "user add username %s groupname %s ip %s port %s mac "MAC_FMT" level %d enable %d type %d%s", user->username, user->group->groupname, user->strip, user->port, MAC_ARG(user->mac), user->level, user->enable, user->type, VTY_NEWLINE);
		}
	}
	pthread_rwlock_unlock(&user_lock);

	return 0;
}

void user_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_user_edit_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_user_add_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_user_del_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_user_edit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_user_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_user_del_cmd);
}

void user_show_cmd_init(unsigned int machine)
{
	if (machine == outer_machine || machine == inner_machine) {
		install_element(VIEW_NODE, &gap_ctl_user_view_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_user_view_o_cmd);

	}

	install_element(VIEW_NODE, &gap_ctl_user_view_cmd);
	install_element(ENABLE_NODE, &gap_ctl_user_view_cmd);
}

void user_init(void)
{
	int idx;
	pthread_rwlock_init(&user_lock, NULL);
	for (idx = 0; idx < GAP_USER_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&user_table[idx]);
	}
}

void user_exit(void)
{
	struct gap_user_rule *user, *next;
	int idx;
	pthread_rwlock_wrlock(&user_lock);
	for (idx = 0; idx < GAP_USER_TAB_SIZE; idx++) {
		list_for_each_entry_safe(user, next, &user_table[idx], n_list) {
			list_del(&user->n_list);
			list_del(&user->g_list);
			list_del(&user->l_list);
			SCFree(user);
			user_count--;
		}
	}
	pthread_rwlock_unlock(&user_lock);
}


