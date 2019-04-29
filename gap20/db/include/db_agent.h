#ifndef _GAP_DB_AGENT_H_
#define _GAP_DB_AGENT_H_
#include "sqlite3.h"  
#include "util-list.h"
#include "app_common.h"

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

static int write_sysevent_log(char *level, char* type, char*content, int priority, int sync){return 0;}
static int write_sys_log(char *module, char* level, char*content, int priority,int sync){return 0;}
static int write_secaudit_log(char *type, char *owner, char *content, int priority, int sync){return 0;}
static int write_secevent_log(char *sip,char *dip,char *user,char *proto, char *level, char *type, char *content, char *rule, int priority,int sync){return 0;}
static int db_log_init(void){return 0;}
static int db_log_exit(void){return 0;}

#endif

