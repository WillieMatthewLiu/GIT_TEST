#ifndef _GAP_CMD_GROUP_H
#define _GAP_CMD_GROUP_H
#include "util-list.h"
#include "util-mem.h"
#include "oscall.h"
#include "gap_ctl_conf.h"
#include "gap_cmd.h"
#include "svrid.h"

struct gap_group_acl
{
	char proto[PROTO_LEN];/* eg: "HTTP" */
	int access;        /*1可以访问， 0不能访问 */
	int dir;/* 1外到内，2内到外，3双向 */
	int rule_mod;

	/* ipset */
	char ipset[IPSET_LEN];
	struct ip_range ir[MAX_IPRANGE_SIZE];
	int num;

	/* extra */
	void *protocol_rule;
};

struct gap_group_rule
{
	struct list_head n_list;
	char groupname[NAME_LEN + 1];
	struct list_head user_list;
	struct gap_group_acl acl[_SVR_ID_COUNT];
};

#define SET_PROTOCOL_RULE_NULL(g, svr_id) \
    do{ (g)->acl[svr_id].protocol_rule = NULL; }while(0)

#define SET_PROTOCOL_RULE_PTR(g, svr_id, ptr) \
    do{ (g)->acl[svr_id].protocol_rule = ptr; }while(0)

typedef void(*delete_proto_rule_func)(void *protocol_rule);
struct gap_group_rule* get_group_by_name(const char *name);
void*  get_protocol_rule(const char *groupname, int srvid);
int set_protocol_rule(const char *groupname, int srvid, void *rule);
void register_delete_proto_rule_callback(int svrid, delete_proto_rule_func callback);
#endif 
