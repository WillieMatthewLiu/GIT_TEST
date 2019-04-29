#ifndef _GAP_CMD_DBSECURITY_H
#define _GAP_CMD_DBSECURITY_H
#include "util-list.h"
#include "gap_cmd.h"
#include "parser_mssql.h"
#include "gap_cmd_timemgr.h"

struct dbsecurity_item_list
{
	struct list_head n_list;
	char *name;
};

struct dbsecurity_rule_group
{
	struct json_object *rule_json; //json

	char groupname[NAME_LEN + 1];
	struct gap_group_rule *group;
	int rule_work; //0: not work, 1: work
	int dbtype;
	int user_name_mode;
	struct list_head user_name_list;
	char *user_name_json_str;
	struct list_head black_operation_list;
	char *black_operation_json_str;
	/* time control */
	char effectime[NAME_LEN + sizeof(TIME_GROUP_SUFFIX)];
	struct time_acl tacl;
};

int dbsecurity_config_write(struct vty *vty);
int dbsecurity_check_rule_work_privilege(const char *dbtype, struct dbsecurity_rule_group *group);
int dbsecurity_access_time_check(const char *dbtype, struct dbsecurity_rule_group *group);
int dbsecurity_access_user_check(const char *dbtype, struct dbsecurity_rule_group *group, const char *username);
int dbsecurity_access_operation_check(const char *dbtype, struct dbsecurity_rule_group *group, const char *operation);

void dbsecurity_cmd_init(void);
void dbsecurity_cmd_exit(void);

#endif 
