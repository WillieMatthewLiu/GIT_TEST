
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
#include "gap_cmd_log.h"
#include "gap_cmd_state.h"
#include "gap_cmd_user.h"
#include "gap_ctl_conf.h"
#include "gap_cmd_group.h"
#include "gap_stgy.h"
#include "json-c.h"

extern struct list_head user_table[GAP_USER_TAB_SIZE];
extern pthread_rwlock_t user_lock;

/*
 *	list: for group lookups
 */
static struct list_head group_list = LIST_HEAD_INIT(group_list);
static pthread_rwlock_t group_lock;
unsigned int group_count = 0;
static void _free_protocol_rule(void *ags) {}
delete_proto_rule_func delete_proto_rule[_SVR_ID_COUNT] = { NULL };

int free_protocol_rule(struct gap_group_rule *group)
{
	struct gap_group_acl* acl = group->acl;
	for (int i = _SVR_ID_NONE; i < _SVR_ID_COUNT; i++, acl++) 
	{
		delete_proto_rule[i](acl->protocol_rule);
	}

	return 0;
}

static int in_range(unsigned int ip, struct gap_group_acl* acl)
{
	int i = 0;
	unsigned int dwIP = ntohl(ip);

	for (; i < acl->num; i++) 
	{
		if ((dwIP >= acl->ir[i].first_ip) && (dwIP <= acl->ir[i].second_ip))
		{
			return 1;
		}
	}

	return 0;
}

void register_delete_proto_rule_callback(int svrid, delete_proto_rule_func callback)
{
	delete_proto_rule[svrid] = callback;
}

struct gap_group_rule* get_group_by_name(const char *name)
{
	struct gap_group_rule *group, *ret = NULL;

	pthread_rwlock_wrlock(&group_lock);
	list_for_each_entry(group, &group_list, n_list) {
		if (0 == strcmp(group->groupname, name)) {
			/* HIT */
			ret = group;
			break;
		}
	}
	pthread_rwlock_unlock(&group_lock);
	return ret;
}

void*  get_protocol_rule(const char *groupname, int srvid)
{
	struct gap_group_rule *group = get_group_by_name(groupname);
	if (group) {
		return group->acl[srvid].protocol_rule;
	}
	return NULL;
}

int set_protocol_rule(const char *groupname, int srvid, void *rule)
{
	struct gap_group_rule *group = get_group_by_name(groupname);
	if (group) {
		group->acl[srvid].protocol_rule = rule;
		return 0;
	}
	return -1;
}

DEFUN(gap_ctl_group_add,
	gap_ctl_group_add_cmd,
	"group add groupname WORD",
	"group command\n"
	"add group rule.\n"
	"groupname\n"
	"name of group\n"
)
{
	struct gap_group_rule *ggr, *group, *ret = NULL;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	pthread_rwlock_wrlock(&group_lock);
	list_for_each_entry(ggr, &group_list, n_list) {
		if (0 == strcmp(ggr->groupname, argv[0])) {
			/* HIT */
			ret = ggr;
			break;
		}
	}
	pthread_rwlock_unlock(&group_lock);

	if (ret) {
		vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	group = SCMalloc(sizeof(struct gap_group_rule));
	if (NULL == group) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	memset(group, 0, sizeof(struct gap_group_rule));
	INIT_LIST_HEAD(&group->user_list);
	strncpy(group->groupname, argv[0], sizeof(group->groupname) - 1);

	pthread_rwlock_wrlock(&group_lock);
	list_add(&group->n_list, &group_list);
	group_count++;
	pthread_rwlock_unlock(&group_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_group_add,
	gap_ctl_group_add_o_cmd,
	"outer group add groupname WORD",
	"outer machine\n"
	"group command\n"
	"add group rule.\n"
	"groupname\n"
	"name of group\n"
);

DEFUN(gap_ctl_group_acl_edit,
	gap_ctl_group_acl_edit_cmd,
	"acl edit group WORD proto PROTOCOL access (0|1) dir (1|2|3) rule_mod (0|1) rule_servers .LINE",
	"acl command\n"
	"edit acl rule\n"
	"group\n"
	"groupname,such as: group1\n"
	"protocol\n"
	"PROTOCOL, such as: FTP,HTTP,TDCS\n"
	"access\n"
	"0:forbid to access\n"
	"1:allow to access\n"
	"direction\n"
	"1:outer to inner\n"
	"2:inner to outer\n"
	"3: two way\n"
	"rule mode\n"
	"0:Blacklist\n"
	"1:Whitelist\n"
	"rule servers\n"
	"server's ip address, such as:192.168.1.1;192.168.5.0/24;192.168.8.1-192.168.8.10\n"
)
{
	struct gap_group_acl *acl = NULL, *ret = NULL;
	struct gap_group_rule *group = NULL;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	char *add = strstr(self->string, "add");
	int svrid = server_idfromstr(argv[1]);
	if (svrid >= _SVR_ID_COUNT || svrid <= _SVR_ID_NONE) {
		vty_result(ERR_CODE_PARAMERROR, ERR_CODE_PARAMERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	pthread_rwlock_wrlock(&group_lock);
	list_for_each_entry(group, &group_list, n_list) {
		if (0 == strcmp(argv[0], group->groupname)) {
			acl = &group->acl[svrid];
			break;
		}
	}

	if (acl == NULL) {
		pthread_rwlock_unlock(&group_lock);
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	strncpy(acl->proto, argv[1], sizeof(acl->proto) - 1);
	acl->access = atoi(argv[2]);
	acl->dir = atoi(argv[3]);
	acl->rule_mod = atoi(argv[4]);
	strncpy(acl->ipset, argv[5], sizeof(acl->ipset) - 1);
	translate_ipset(acl->ipset, acl->ir, &acl->num);
	pthread_rwlock_unlock(&group_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_group_acl_edit,
	gap_ctl_group_acl_edit_o_cmd,
	"outer acl edit group WORD proto PROTOCOL access (0|1) dir (1|2|3) rule_mod (0|1) rule_servers .LINE",
	"outer machine\n"
	"acl command\n"
	"edit acl rule\n"
	"group\n"
	"groupname,such as: group1\n"
	"protocol\n"
	"PROTOCOL, such as: FTP,HTTP,TDCS\n"
	"access\n"
	"0:forbid to access\n"
	"1:allow to access\n"
	"direction\n"
	"1:outer to inner\n"
	"2:inner to outer\n"
	"3: two way\n"
	"rule mode\n"
	"0:Blacklist\n"
	"1:Whitelist\n"
	"rule servers\n"
	"server's ip address, such as:192.168.1.1;192.168.5.0/24;192.168.8.1-192.168.8.10\n");

DEFUN(gap_ctl_group_view,
	gap_ctl_group_view_cmd,
	"show group {pgindex <0-2147483647>|pgsize <1-2147483647>|name NANE}",
	SHOW_STR
	"show group rule.(groupname/ protocol access direction mode servers)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n"
	"show group by name\n"
	"name string\n")
{
	const char *name = NULL;
	struct gap_group_rule *group;
	struct gap_group_acl *acl;
	struct in_addr   inaddr;
	int i;
	/* 查询命令是否远端执行 */
	SHOW_CMD_RUN();

	int count = 0;
	char *pageindex = argv[0];
	char *pagesize = argv[1];
	name = argv[2];
	if (pageindex == NULL) {
		pageindex = DEFAULT_PGINDEX;
	}
	if (pagesize == NULL) {
		pagesize = DEFAULT_PGSIZE;
	}
	int pgindex = atoi(pageindex);
	int pgsize = atoi(pagesize);

	pthread_rwlock_rdlock(&group_lock);
	list_for_each_entry(group, &group_list, n_list) {
		if ((pgindex == 0) || (count >= ((pgindex - 1)*pgsize) && count < (pgindex*pgsize))) {
			if (name && (*name != '\0') && (strcmp(name, group->groupname) != 0)) {
				continue;
			}
			vty_out(vty, "%s%s", group->groupname, VTY_NEWLINE);
			struct gap_group_acl *acl = group->acl;
			for (i = _SVR_ID_NONE + 1; i < _SVR_ID_COUNT; i++, acl++) {
				if ((strlen(acl->proto))) {
					vty_out(vty, "    %-8s  %d  %d  %d  %s%s", acl->proto, acl->access, acl->dir, acl->rule_mod, acl->ipset, VTY_NEWLINE);
				}
			}
		}
		count++;
	}
	pthread_rwlock_unlock(&group_lock);

	vty_out(vty, "[pageindex=%d,pagesize=%d,totalline=%d]%s", pgindex, pgsize, count, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_group_view,
	gap_ctl_group_view_o_cmd,
	"show outer group {pgindex <0-2147483647>|pgsize <1-2147483647>|name NANE}",
	SHOW_STR
	"outer machine\n"
	"show group rule.(groupname/ index protocol access direction mode servers)\n"
	"pageindex\n"
	"0-2147483647\n"
	"pagesize\n"
	"1-2147483647\n");

DEFUN(gap_ctl_group_del,
	gap_ctl_group_del_cmd,
	"group delete groupname WORD",
	"group command\n"
	"delete group rule.\n"
	"groupname\n"
	"name of group\n"
)
{
	struct gap_group_rule *group, *next;
	int del = 0;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	pthread_rwlock_wrlock(&group_lock);
	list_for_each_entry_safe(group, next, &group_list, n_list) {
		if (0 == strcmp(argv[0], group->groupname)) {
			/* check referenced */
			if (!list_empty(&group->user_list)) {
				pthread_rwlock_unlock(&group_lock);
				vty_result(ERR_CODE_REFERENCDERR, ERR_CODE_REFERENCDERR_DESC);
				return CMD_ERR_NOTHING_TODO;
			}

			/* 释放扩展规则 */
			if (free_protocol_rule(group)) {
				pthread_rwlock_unlock(&group_lock);
				vty_result(ERR_CODE_CALLBACKERR, ERR_CODE_CALLBACKERR_DESC);
				return CMD_ERR_NOTHING_TODO;
			}

			group_count--;
			list_del(&group->n_list);
			SCFree(group);
			del = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&group_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_group_del,
	gap_ctl_group_del_o_cmd,
	"outer group delete groupname WORD",
	"outer machine\n"
	"group command\n"
	"delete group rule.\n"
	"groupname\n"
	"name of group\n"
);

static struct gap_group_rule *get_group(char *name)
{
	struct gap_group_rule *ggr, *group, *ret = NULL;

	group = SCMalloc(sizeof(struct gap_group_rule));
	if (NULL == group) {
		return NULL;
	}
	memset(group, 0, sizeof(struct gap_group_rule));
	INIT_LIST_HEAD(&group->user_list);
	strncpy(group->groupname, name, sizeof(group->groupname) - 1);

	pthread_rwlock_wrlock(&group_lock);
	list_for_each_entry(ggr, &group_list, n_list) {
		if (0 == strcmp(ggr->groupname, group->groupname)) {
			/* HIT */
			ret = ggr;
			break;
		}
	}

	if (NULL == ret) {
		group_count++;
		list_add(&group->n_list, &group_list);
		ret = group;
	}
	else {
		SCFree(group);
	}
	pthread_rwlock_unlock(&group_lock);
	return ret;
}

static void get_acl(struct gap_group_rule *group, char *proto, struct json_object *jobj)
{
	struct json_object *jproto = json_object_object_get(jobj, proto);
	if (jproto == NULL)
		return;
	char *access = json_object_get_string(json_object_object_get(jproto, "access"));
	if (access == NULL)
		return;
	char *dir = json_object_get_string(json_object_object_get(jproto, "direction"));
	if (dir == NULL)
		return;
	char *address = json_object_get_string(json_object_object_get(jproto, "mode"));
	if (address == NULL)
		return;
	char *ips = json_object_get_string(json_object_object_get(jproto, "ips"));
	if (ips == NULL)
		return;

	int svrid = server_idfromstr(proto);
	struct gap_group_acl *acl = &group->acl[svrid];

	pthread_rwlock_wrlock(&group_lock);
	/*赋值*/
	snprintf(acl->proto, sizeof(acl->proto), "%s", proto);
	acl->access = atoi(access);
	acl->dir = atoi(dir);
	acl->rule_mod = atoi(address);
	if (strlen(ips) == 0) {
		strncpy(acl->ipset, TEMPLATE_IP, sizeof(acl->ipset) - 1);
	}
	else {
		strncpy(acl->ipset, ips, sizeof(acl->ipset) - 1);
	}
	translate_ipset(acl->ipset, acl->ir, &acl->num);
	pthread_rwlock_unlock(&group_lock);
	return;
}

static struct _SVR_ID_NAME_MAP
{
	enum SVR_ID id;
	const char *name;
} _svrid_to_name_map[_SVR_ID_COUNT] = SVR_ID_TO_NAME_MAP;

DEFUN_HIDDEN(gap_ctl_group_add_json,
	gap_ctl_group_add_json_cmd,
	"group add .JSON",
	"group command\n"
	"add group rule.\n"
	"Json format string\n")
{
	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	struct json_object *nobj;
	struct json_object *jobj = json_tokener_parse(argv[0]);
	if (!jobj) {
		vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* get group name */
	struct gap_group_rule *group = NULL;
	if (json_object_object_get_ex(jobj, "name", &nobj)) {
		char *name = json_object_get_string(nobj);
		group = get_group(name);
	}

	if (group == NULL) {
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		json_object_put(jobj);
		return CMD_ERR_NOTHING_TODO;
	}

	/* get acl */
	for (int i = 0; i < countof(_svrid_to_name_map); i++) {
		const char* proto = _svrid_to_name_map[i].name;
		get_acl(group, proto, jobj);
	}

	json_object_put(jobj);
	return CMD_SUCCESS;
}

ALIAS_HIDDEN(gap_ctl_group_add_json,
	gap_ctl_group_add_json_o_cmd,
	"outer group add .JSON",
	"outer machine\n"
	"group command\n"
	"add group rule.\n"
	"Json format string\n");

DEFUN_HIDDEN(gap_ctl_group_wml_show,
	gap_ctl_group_wml_show_cmd,
	"show wml group",
	SHOW_STR
	"Web Module\n"
	"user group name list\n")
{
	struct gap_group_rule *group;

	/* 查询命令是否远端执行 */
	SHOW_CMD_RUN();

	pthread_rwlock_rdlock(&group_lock);
	list_for_each_entry(group, &group_list, n_list) {
		vty_out(vty, "%s,", group->groupname);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	pthread_rwlock_unlock(&group_lock);
	return CMD_SUCCESS;
}

ALIAS_HIDDEN(gap_ctl_group_wml_show,
	gap_ctl_group_wml_show_o_cmd,
	"show wml outer group",
	SHOW_STR
	"Web Module\n"
	"outer\n"
	"\n");

int check_group_privilege(struct acl_data* ad, struct gap_group_rule* group, char proto[], char rule[], int len)
{
	struct gap_group_acl *acl;
	int ret = 0;

	snprintf(rule, len, "group:%s", group->groupname);
	int svrid = server_idfromstr(proto);
	if (svrid >= _SVR_ID_COUNT || svrid <= _SVR_ID_NONE)
	{
		SCLogInfo("Protocol not support.");
		return -1;
	}

	pthread_rwlock_rdlock(&group_lock);
	acl = &group->acl[svrid];
	if (strlen(acl->proto))
	{
		if (acl->access == 0) 
		{
			ret = -1;
			SCLogInfo("Access not allowed.");
			goto out;
		}

		if (!((acl->dir) & (ad->dir))) 
		{
			ret = -1;
			SCLogInfo("Dir err.");
			goto out;
		}

		if (in_range(ad->dip, acl)) 
		{
			if (0 == acl->rule_mod) 
			{
				ret = -1;
				SCLogInfo("In blacklist IP %s.", ad->c_dip);
				goto out;
			}
		}
		else
		{
			if (1 == acl->rule_mod) 
			{
				ret = -1;
				SCLogInfo("Out whitelist IP %s.", ad->c_dip);
				goto out;
			}
		}
	}

out:
	pthread_rwlock_unlock(&group_lock);

	return ret;
}

int group_config_write(struct vty *vty)
{
	struct gap_group_rule *group;
	struct gap_group_acl *acl;

	pthread_rwlock_rdlock(&group_lock);
	list_for_each_entry(group, &group_list, n_list) {
		vty_out(vty, "group add groupname %s%s", group->groupname, VTY_NEWLINE);
		struct gap_group_acl *acl = group->acl;
		for (int i = _SVR_ID_NONE + 1; i < _SVR_ID_COUNT; i++, acl++) {
			if (strlen(acl->proto)) {
				vty_out(vty, "acl edit group %s proto %s access %d dir %d rule_mod %d rule_servers %s%s", group->groupname, acl->proto, acl->access, acl->dir, acl->rule_mod, acl->ipset, VTY_NEWLINE);
			}
		}
	}
	pthread_rwlock_unlock(&group_lock);
	return 0;
}

void group_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_group_del_cmd);
	install_element(CONFIG_NODE, &gap_ctl_group_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_group_acl_edit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_group_add_json_cmd);

	install_element(CONFIG_NODE, &gap_ctl_group_del_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_group_add_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_group_acl_edit_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_group_add_json_o_cmd);
}

void group_show_cmd_init(unsigned int machine)
{
	if (machine == outer_machine || machine == inner_machine) {
		install_element(VIEW_NODE, &gap_ctl_group_view_o_cmd);
		install_element(VIEW_NODE, &gap_ctl_group_wml_show_cmd);
		install_element(VIEW_NODE, &gap_ctl_group_wml_show_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_group_view_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_group_wml_show_cmd);
		install_element(ENABLE_NODE, &gap_ctl_group_wml_show_o_cmd);
	}

	install_element(VIEW_NODE, &gap_ctl_group_view_cmd);
	install_element(ENABLE_NODE, &gap_ctl_group_view_cmd);
}

void group_init(void)
{
	int i;
	for (i = 0; i < _SVR_ID_COUNT; i++) {
		delete_proto_rule[i] = _free_protocol_rule;
	}
	pthread_rwlock_init(&group_lock, NULL);
}

void group_exit(void)
{
	struct gap_group_rule *group, *next;
	pthread_rwlock_wrlock(&group_lock);
	list_for_each_entry_safe(group, next, &group_list, n_list) {
		/* 释放扩展规则 */
		free_protocol_rule(group);

		list_del(&group->n_list);
		SCFree(group);
		group_count--;
	}
	pthread_rwlock_unlock(&group_lock);
}


