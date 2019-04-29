
#include "app_common.h"

#include <zebra.h>

#include <json-c/json.h>

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

#include <iconv.h>

#include <readline/readline.h>
#include <readline/history.h>
#include <termios.h>
#include "command.h"
#include "lib/memory.h"
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
#include "parser_mssql.h"
#include "parser_mysql.h"
#include "pktfilter.h"
#include "gap_cmd_group.h"
#include "gap_cmd_http.h"
#include "json-c.h"
#include "hash.h"
#include "gap_cmd_dbsecurity.h"

extern int check_time_privilege(struct time_acl *tacl);
extern void timemgr_put(struct time_acl *acl);
extern void timemgr_get(struct time_acl *acl, char *name);

struct hash *dbsecurity_table;
pthread_rwlock_t dbsecurity_lock;

static unsigned int dbsecurity_hashkey(struct dbsecurity_rule_group *group)
{
	return jhash(group->groupname, strlen(group->groupname), 0);
}

static int dbsecurity_hashcmp(const struct dbsecurity_rule_group *group1, const struct dbsecurity_rule_group *group2)
{
	return (!strcmp(group1->groupname, group2->groupname) && (group1->dbtype == group2->dbtype));
}

static void dbsecurity_write_pvty(struct hash_backet *bug, struct vty *vty)
{
	struct dbsecurity_rule_group *group = bug->data;
	if (NULL != group)
	{
		if (NULL != group->rule_json)
		{
			vty_out(vty, "protocol-dbsecurity add rule %s%s", JSON_FORMAT_STR(group->rule_json), VTY_NEWLINE);
		}
	}
}

static void dbsecurity_show_pvty(struct hash_backet *bug, struct vty *vty)
{
	struct dbsecurity_rule_group *group = bug->data;
	if (NULL != group)
	{
		if (NULL != group->rule_json)
		{
			vty_out(vty, "%s%s", JSON_FORMAT_STR(group->rule_json), VTY_NEWLINE);
		}
	}
}

static int parser_dbtype(const char *dbtype)
{
	int type = -1;

	if (NULL == dbtype)
		return type;

	if (strcmp(dbtype, "MYSQL") == 0)
	{
		type = SVR_ID_MYSQL;
	}
	else if (strcmp(dbtype, "SQLSERVER") == 0)
	{
		type = SVR_ID_MSSQL;
	}
	else if (strcmp(dbtype, "ORACLE") == 0)
	{
		type = SVR_ID_ORCL;
	}
	else
	{
		SCLogInfo("dbtype string is wrong\n");
	}
	return type;
}

static struct dbsecurity_rule_group *dbsecurity_rule_group_new(const char *name, int db_type)
{
	struct dbsecurity_rule_group *group = NULL;

	group = SCMalloc(sizeof(struct dbsecurity_rule_group));
	if (NULL == group)
	{
		SCLogError("SCMalloc dbsecurity_rule_group fail.\n");
		return NULL;
	}

	memset(group, 0, sizeof(*group));
	strncpy(group->groupname, name, NAME_LEN);
	group->dbtype = db_type;

	INIT_LIST_HEAD(&group->user_name_list);
	INIT_LIST_HEAD(&group->black_operation_list);

	return group;
}

static void dbsecurity_add_rule_group(struct dbsecurity_rule_group *group)
{
	hash_get(dbsecurity_table, group, hash_alloc_intern);
}

void dbsecurity_del_rule_group(void *group_rule)
{
	if (NULL == group_rule)
		return;

	struct dbsecurity_rule_group *group = (struct dbsecurity_rule_group*)group_rule;
	struct dbsecurity_item_list *item = NULL;
	struct dbsecurity_item_list *item_n = NULL;

	SET_PROTOCOL_RULE_NULL(group->group, group->dbtype);
	pthread_rwlock_wrlock(&dbsecurity_lock);
	hash_release(dbsecurity_table, group);
	pthread_rwlock_unlock(&dbsecurity_lock);

	if (NULL != group->rule_json)
	{
		json_object_put(group->rule_json);
	}
	if (NULL != group->user_name_json_str)
	{
		SCFree(group->user_name_json_str);
	}
	if (NULL != group->black_operation_json_str)
	{
		SCFree(group->black_operation_json_str);
	}

	timemgr_put(&group->tacl);

	list_for_each_entry_safe(item, item_n, &group->user_name_list, n_list)
	{
		SCLogInfo("del user_name_item:%s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}
	list_for_each_entry_safe(item, item_n, &group->black_operation_list, n_list)
	{
		SCLogInfo("del black_operation_item:%s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	SCFree(group);
}

int dbsecurity_check_rule_work_privilege(const char *dbtype, struct dbsecurity_rule_group *group)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	int type = parser_dbtype(dbtype);

	pthread_rwlock_rdlock(&dbsecurity_lock);
	if (1 == group->rule_work)
	{
		ret = -1;
	}
	pthread_rwlock_unlock(&dbsecurity_lock);
	return ret;
}

int dbsecurity_access_time_check(const char *dbtype, struct dbsecurity_rule_group *group)
{
	if (NULL == group)
		return 0;

	int ret = 0;
	int type = parser_dbtype(dbtype);

	pthread_rwlock_rdlock(&dbsecurity_lock);
	if (0 != check_time_privilege(&group->tacl))
	{
		SCLogInfo("hit effective time: prohibit access.\n");
		ret = -1;
	}
	pthread_rwlock_unlock(&dbsecurity_lock);
	return ret;
}

int dbsecurity_access_user_check(const char *dbtype, struct dbsecurity_rule_group *group, const char *username)
{
	int access_allow = 0;
	int hit_it = 0;
	struct dbsecurity_item_list *item = NULL;

	if (NULL == group || NULL == username)
	{
		return 0;
	}

	pthread_rwlock_rdlock(&dbsecurity_lock);
	do
	{
		int type = parser_dbtype(dbtype);
		if (type < 0)
		{
			SCLogInfo("dbtype is error\n");
			break;
		}
		list_for_each_entry(item, &group->user_name_list, n_list)
		{
			if (0 == strcmp(username, item->name))
			{
				hit_it = 1;
				break;
			}
		}
	} while (0);

	if ((1 == hit_it && 0 == group->user_name_mode) || (0 == hit_it && 1 == group->user_name_mode))
	{
		SCLogInfo("hit black db user or not in while db user\n");
		access_allow = -1;
	}

	pthread_rwlock_unlock(&dbsecurity_lock);
	return access_allow;
}

int dbsecurity_access_operation_check(const char *dbtype, struct dbsecurity_rule_group *group, const char *operation)
{
	if (NULL == group)
		return 0;
	int access_allow = -1;
	struct dbsecurity_item_list *item = NULL;
	pthread_rwlock_rdlock(&dbsecurity_lock);
	do
	{
		int type = parser_dbtype(dbtype);
		if (type < 0)
		{
			SCLogInfo("dbtype is error\n");
			break;
		}
		list_for_each_entry(item, &group->black_operation_list, n_list)
		{
			if (0 == strcasecmp(operation, item->name))
			{
				access_allow = 0;
				SCLogInfo("hit black operation: prohibit access.\n");
				break;
			}
		}
	} while (0);
	pthread_rwlock_unlock(&dbsecurity_lock);
	return access_allow;
}

static int dbsecurity_parse_json_effectime(struct dbsecurity_rule_group *group)
{
	char *effectime = json_object_get_string(json_object_object_get(group->rule_json, "effectime"));
	if (NULL == effectime)
	{
		SCLogInfo("dbsecurity_parse_json_effectime, there is no 'effectime' rule");
		return 0;
	}
	timemgr_put(&group->tacl);
	strncpy(group->effectime, effectime, strlen(effectime) + 1);
	timemgr_get(&group->tacl, group->effectime);
	return 0;
}

static int json_to_item_str(struct json_object *items_json, struct list_head *items_list_head, char **items_str)
{
	int idx = 0;
	const char *json_item_str = NULL;
	const char *json_item_one_str = NULL;
	struct dbsecurity_item_list *item = NULL;
	struct dbsecurity_item_list *item_n = NULL;

	json_item_str = json_object_to_json_string_ext(items_json, 0);
	SCLogInfo("add json_item_str:%s, old json_item_str:%s\n", json_item_str, *items_str);


	/* items_str never changed */
	if ((NULL != *items_str) && (0 == strcmp(*items_str, json_item_str)))
	{
		return 0;
	}

	/* clear items_str */
	if (NULL != *items_str)
	{
		SCFree(*items_str);
		*items_str = NULL;
	}

	/* add items_str */
	*items_str = SCStrdup(json_item_str);
	if (NULL == *items_str)
	{
		SCLogInfo("json_to_item_str: *items_str is NULL\n");
		return -1;
	}

	/* clear items_list */
	list_for_each_entry_safe(item, item_n, items_list_head, n_list)
	{
		SCLogInfo("del item: %s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	/* add items_list */
	for (idx = 0; idx < json_object_array_length(items_json); idx++)
	{
		json_item_one_str = json_object_get_string(json_object_array_get_idx(items_json, idx));
		item = SCMalloc(sizeof(struct dbsecurity_item_list));
		if (NULL == item)
		{
			SCLogInfo("json_to_item_str: SCMalloc error\n");
			return -1;
		}
		item->name = SCStrdup(json_item_one_str);
		list_add(&item->n_list, items_list_head);
		SCLogInfo("add item: %s\n", item->name);
	}

	return 0;
}

static int dbsecurity_parse_json_username(struct dbsecurity_rule_group *group)
{
	int ret = 0;
	struct json_object *username_json = NULL;
	struct json_object *username_val_json = NULL;
	username_json = json_object_object_get(group->rule_json, "user_name");
	if (NULL == username_json)
	{
		SCLogInfo("dbsecurity_parse_json_username: there is no 'user_name' rule");
		return -1;
	}
	group->user_name_mode = atoi(json_object_get_string(json_object_object_get(username_json, "mode")));
	username_val_json = json_object_object_get(username_json, "value");

	ret = json_to_item_str(username_val_json, &group->user_name_list, &group->user_name_json_str);
	return ret;
}

static int dbsecurity_parse_json_operation(struct dbsecurity_rule_group *group)
{
	int ret = 0;
	struct json_object *operation_json = NULL;
	operation_json = json_object_object_get(group->rule_json, "black_operation");
	if (NULL == operation_json)
	{
		SCLogInfo("dbsecurity_parse_json_operation: there is no 'black_operation' rule");
		return -1;
	}

	ret = json_to_item_str(operation_json, &group->black_operation_list, &group->black_operation_json_str);
	return ret;
}

/*
{
	"group_name":"G1",
	"rule_work":"1",
	"effectime":"afternoon",
	"dbtype":"MYSQL",
	"user_name":{"mode": "0", "value":["root1","root2"]},
	"black_operation":["select", "update"]
}
*/
DEFUN(gap_ctl_dbsecurity_add,
	gap_ctl_dbsecurity_add_cmd,
	"protocol-dbsecurity add rule .JSON",
	"dbsecurity command\n"
	"add dbsecurity rule\n"
	"rule\n"
	"json string,eg:{}\n")
{
	char *groupname = NULL;
	int dbtype = 0;
	char *rule_json_str = NULL;
	struct json_object *jobj = NULL;
	struct dbsecurity_rule_group *group = NULL;

	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	pthread_rwlock_wrlock(&dbsecurity_lock);
	rule_json_str = argv_concat(argv, argc, 0);
	SCLogInfo("add rule_json_str:%s\n", rule_json_str);
	jobj = json_tokener_parse(rule_json_str);
	if (NULL == jobj)
	{
		XFREE(MTYPE_TMP, rule_json_str);
		vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
		goto done;
	}

	/* add dbsecurity rule group */
	groupname = json_object_get_string(json_object_object_get(jobj, "group_name"));
	dbtype = parser_dbtype(json_object_get_string(json_object_object_get(jobj, "dbtype")));

	group = get_protocol_rule(groupname, dbtype);
	if (NULL == group)
	{
		group = dbsecurity_rule_group_new(groupname, dbtype);
		if (NULL == group)
		{
			vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
			goto done;
		}
		group->group = get_group_by_name(groupname);
		dbsecurity_add_rule_group(group);
	}

	/* add rule json */
	if (NULL != group->rule_json)
	{
		json_object_put(group->rule_json);
	}
	group->rule_json = jobj;

	/* add rule work */
	group->rule_work = atoi(json_object_get_string(json_object_object_get(group->rule_json, "rule_work")));

	/* add effective time */
	if (0 != dbsecurity_parse_json_effectime(group))
	{
		goto done;
	}
	/* add dbsecurity group username */
	if (0 != dbsecurity_parse_json_username(group))
	{
		goto done;
	}
	/* add dbsecurity group black_operation */
	if (0 != dbsecurity_parse_json_operation(group))
	{
		goto done;
	}

	/* set protocol for group rule */
	if (0 != set_protocol_rule(groupname, dbtype, group))
	{
		goto done;
	}

done:
	XFREE(MTYPE_TMP, rule_json_str);
	pthread_rwlock_unlock(&dbsecurity_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_dbsecurity_add,
	gap_ctl_dbsecurity_add_outer_cmd,
	"outer protocol-dbsecurity add rule .JSON",
	"outer machine\n"
	"dbsecurity command\n"
	"add dbsecurity rule\n"
	"rule\n"
	"json string,eg:{}\n");

DEFUN(gap_ctl_dbsecurity_del,
	gap_ctl_dbsecurity_del_cmd,
	"protocol-dbsecurity delete groupname NAME dbtype DB",
	"dbsecurity command\n"
	"delete dbsecurity rule\n"
	"groupname\n"
	"group name\n"
	"dbtype\n"
	"dbtype name\n")
{
	struct dbsecurity_rule_group *group = NULL;
	const char *groupname = argv[0];
	int dbtype = parser_dbtype(argv[1]);
	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	pthread_rwlock_rdlock(&dbsecurity_lock);
	group = get_protocol_rule(groupname, dbtype);
	pthread_rwlock_unlock(&dbsecurity_lock);

	if (NULL != group)
	{
		dbsecurity_del_rule_group(group);
	}
	else
	{
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_dbsecurity_del,
	gap_ctl_dbsecurity_del_outer_cmd,
	"outer protocol-dbsecurity delete groupname NAME dbtype DB",
	"outer machine\n"
	"dbsecurity command\n"
	"delete dbsecurity rule\n"
	"groupname\n"
	"group name\n"
	"dbtype\n"
	"dbtype name\n");

DEFUN(gap_ctl_dbsecurity_view,
	gap_ctl_dbsecurity_view_cmd,
	"show protocol-dbsecurity {groupname NAME dbtype DB}",
	SHOW_STR
	"dbsecurity rule\n"
	"groupname\n"
	"name\n"
	"dbtype\n"
	"dbtype name\n")
{
	struct dbsecurity_rule_group *group = NULL;
	const char *groupname = argv[0];
	int dbtype = parser_dbtype(argv[1]);
	SHOW_CMD_RUN();

	pthread_rwlock_rdlock(&dbsecurity_lock);
	if (NULL != groupname)
	{
		group = get_protocol_rule(groupname, dbtype);
		if (NULL != group)
		{
			if (NULL != group->rule_json)
			{
				vty_out(vty, "%s%s", JSON_FORMAT_STR(group->rule_json), VTY_NEWLINE);
			}
		}
	}
	else
	{
		hash_iterate(dbsecurity_table, dbsecurity_show_pvty, vty);
	}
	pthread_rwlock_unlock(&dbsecurity_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_dbsecurity_view,
	gap_ctl_dbsecurity_view_o_cmd,
	"show outer protocol-dbsecurity {groupname NAME dbtype DB}",
	SHOW_STR
	"outer machine\n"
	"dbsecurity rule\n"
	"groupname\n"
	"name\n"
	"dbtype\n"
	"dbtype name\n");

static struct cmd_node dbsecurity_node =
{
	.node = PROTO_DBSECURITY_AUDIT,
	.prompt = "",
	.vtysh = 1
};
int dbsecurity_config_write(struct vty *vty)
{
	pthread_rwlock_rdlock(&dbsecurity_lock);
	hash_iterate(dbsecurity_table, dbsecurity_write_pvty, vty);
	pthread_rwlock_unlock(&dbsecurity_lock);
	return 0;
}

static void dbsecurity_conf_cmd_init(void)
{
	install_element(VIEW_NODE, &gap_ctl_dbsecurity_view_cmd);
	install_element(VIEW_NODE, &gap_ctl_dbsecurity_view_o_cmd);

	install_element(ENABLE_NODE, &gap_ctl_dbsecurity_view_cmd);
	install_element(ENABLE_NODE, &gap_ctl_dbsecurity_view_o_cmd);

	install_element(CONFIG_NODE, &gap_ctl_dbsecurity_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_dbsecurity_del_cmd);

	install_element(CONFIG_NODE, &gap_ctl_dbsecurity_add_outer_cmd);
	install_element(CONFIG_NODE, &gap_ctl_dbsecurity_del_outer_cmd);

	install_node(&dbsecurity_node, dbsecurity_config_write);
}

void dbsecurity_cmd_init(void)
{
	pthread_rwlock_init(&dbsecurity_lock, NULL);
	dbsecurity_table = hash_create(dbsecurity_hashkey, dbsecurity_hashcmp);
	dbsecurity_conf_cmd_init();
	register_delete_proto_rule_callback(SVR_ID_MYSQL, dbsecurity_del_rule_group);
	register_delete_proto_rule_callback(SVR_ID_ORCL, dbsecurity_del_rule_group);
	register_delete_proto_rule_callback(SVR_ID_MSSQL, dbsecurity_del_rule_group);
}

void dbsecurity_cmd_exit(void)
{
	pthread_rwlock_wrlock(&dbsecurity_lock);
	hash_clean(dbsecurity_table, dbsecurity_del_rule_group);
	hash_free(dbsecurity_table);
	pthread_rwlock_unlock(&dbsecurity_lock);
}
