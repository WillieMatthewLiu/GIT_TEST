#ifndef _GAP_DB_AGENT_H_
#define _GAP_DB_AGENT_H_
#include "sqlite3.h"  
#include "util-list.h"
#include "app_common.h"

#define GAP_LOGIN_TABLE      "login_table"
#define GAP_OP_TABLE      "op_table"
#define GAP_SYS_TABLE      "sys_table"
#define GAP_AUDIT_TABLE      "audit_table"
#define GAP_SEC_EVENT_TABLE      "sec_event_table"
#define GAP_SYS_EVENT_TABLE      "sys_event_table"

#define SEC_EVT_LEVEL_CRITICAL  "critical"
#define SEC_EVT_LEVEL_WARN  "warn"
#define SEC_EVT_TYPE     "security event"

#define SYS_EVT_LEVEL_CRITICAL  "critical"
#define SYS_EVT_LEVEL_WARN  "warn"
#define SYS_EVT_LEVEL_NORMAL  "normal"
#define SYS_EVT_TYPE     "system event"

enum log_priority
{
	PRI_HIGH = 0,
	PRI_MIDDLE = 1,
	PRI_LOW = 2,
	PRI_MAX
};

int write_login_log(char *ip, char *user, char *state, char *content, int priority, int sync);
int write_op_log(char *ip, char *user, char *op, char *type, char *content, int priority, int sync);
static inline int write_sys_log(char *module, char* level, char*content, int priority, int sync) {};
int write_audit_log(char *user, char *proto, char *url, char *content, int priority, int sync);
static inline int write_secaudit_log(char *type, char *owner, char *content, int priority, int sync) { return 0; };
static inline int write_secevent_log(char *sip, char *dip, char *user, char *proto, char *level, char *type, char *content, char *rule, int priority, int sync) { return 0; };
int write_sysevent_log(char *level, char* type, char*content, int priority, int sync);
char* select_login_log(int priority, char *stime, char *etime, char *ip, char *user, char *state, char *content, char *pageindex, char *pagesize, int sync);
char *select_op_log(int priority, char *stime, char *etime, char *ip, char *user, char *op, char *type, char *pageindex, char *pagesize, int sync);
char *select_sys_log(int priority, char *stime, char *etime, char *module, char *level, char *content, char *pageindex, char *pagesize, int sync);
char *select_audit_log(int priority, char *stime, char *etime, char *user, char *proto, char *url, char *content, char *pageindex, char *pagesize, int sync);
char *select_secaudit_log(int priority, char *stime, char *etime, char *type, char *owner, char *content, char *pageindex, char *pagesize, int sync);
char *select_secevent_log(int priority, char *stime, char *etime, char *sip, char *dip, char *proto, char *pageindex, char *pagesize, int sync);
char *select_sysevent_log(int priority, char *stime, char *etime, char *content, char *pageindex, char *pagesize, int sync);
int delete_table_log(char *table, int priority, int sync);
char *select_table_log(char *table, char *id, int priority, int sync);
char *select_table_count(char *table, char *sql, int priority, int sync);
char *select_table_size(void);

#endif

