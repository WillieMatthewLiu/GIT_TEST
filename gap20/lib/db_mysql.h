#ifndef _GAP_MYSQL_H
#define _GAP_MYSQL_H
#include "cmd_common.h"

#define INNER_BOARDTYPE  "inner"
#define OUTER_BOARDTYPE  "outer"

#define MYSQL_SEC_EVT_TYPE "security event"

enum mysql_log_level
{
	l_critical = 0,
	l_error = 1,
	l_warn = 2,
	l_info = 3
};

enum mysql_table
{
	operationlogs,
	syslogs,
	eventauditlogs,
	accessauditlogs,
	sessionlogs,
	max_table
};

enum mysql_db
{
	INNER_DB = 0,
	OUTER_DB = 1,
	REMOTE_DB = 2,
	SCHEMA_DB = 3,
	MAX_DB
};

enum sql_action
{
	action_insert,
	action_select,
	action_update,
	action_delete,
	action_insert_getid
};
//系统运行配置信息
typedef struct _DBConfigData
{
	char            m_chDBServerIP[60];  			//数据库服务器的IP地址
	int             m_nDBServerPort;  				//数据库的服务端口
	char            m_chDBName[60];  			    //数据库名称
	char            m_chDBUserName[60];  			//数据库用户名
	char            m_chDBPassword[40];  			//数据库用户口令
}DBConfigData;

DBConfigData g_rDBConfig;

#define Abs(x) ((x)<0?(-(x)):(x))
#define DATABASEFILEPATH  "/etc/database.conf"		//Database配置文件的路径

#define DEFAULT_SWITCH 1							/* 默认开启*/
#define DEFAULT_MAX_SIZE 200						/* 默认最大容量(单位:M) */
#define DEFAULT_WARN_SIZE 160						/* 默认告警容量(单位:M)  */
#define MYSQL_USERNAME								"admin"
#define MYSQL_PASSWD								"admin123!@#"

#define MYSQL_PORT 3306

#define DATABASE_MYSQL								"gapdb"
#define MYSQL_OP_TABLE								"operationlogs"
#define MYSQL_SYS_TABLE								"syslogs"
#define MYSQL_EVENT_AUDIT_TABLE						"eventauditlogs"
#define MYSQL_ACCESS_AUDIT_TABLE					"accessauditlogs"
#define MYSQL_SESSION_TABLE							"sessionlogs"

#define AUDIT_SWITCH_FILE							"/var/run/audit_log_disable"
#define AUDIT_VOLUME_FILE							"/var/run/audit_volume_size"

#define SQL_INSERT_OP_FMT \
    "insert into "MYSQL_OP_TABLE"(boardtype, ip, user, op, accesstype, content, result) values(\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',%d)"

#define SQL_INSERT_SYSLOG_FMT \
    "insert into "MYSQL_SYS_TABLE"(boardtype, module, level, content) values(\'%s\',\'%s\',%d,\'%s\')"

#define SQL_INSERT_EVENTAUDITLOGS_FMT \
    "insert into "MYSQL_EVENT_AUDIT_TABLE"(boardtype, user, module, action, content) values(%s, %s, %s, %s,%s)"


#define INSERT_SYS_LOG(module, level, content) do{\
    char sql[2048]={0};\
    snprintf(sql, 2048, SQL_INSERT_SYSLOG_FMT, BOARDTYPE_STR, module, level, content);\
    insert_into(sql); \
}while(0)

static inline void insert_sys_log(const char * module, int level, char *format, ...)
{
#define CMD_BUFLEN   2048
	char buf[CMD_BUFLEN];
	va_list ap;
	int len = 0;

	va_start(ap, format);
	len += vsnprintf(buf + len, CMD_BUFLEN - len, format, ap);
	buf[CMD_BUFLEN - 1] = '\0';
	va_end(ap);

	INSERT_SYS_LOG(module, level, buf);
}

#define INSERT_EVENTAUDIT_LOG(user, module, action, content) do{\
    if(access(AUDIT_SWITCH_FILE, F_OK)!= 0){\
        char sql[2048]={0};\
        snprintf(sql, 2048, SQL_INSERT_EVENTAUDITLOGS_FMT, BOARDTYPE_STR, user, module, action, content);\
        insert_into(sql); \
    }\
}while(0)

#define INSERT_ACCESSAUDIT_LOG_FMT \
    "insert into "MYSQL_ACCESS_AUDIT_TABLE"(boardtype, sessionID,sip,dip,protocol,sport,dport,application,\
    user,hostname,level,rule,rulehitresult,packetlength,content) \
    values(\'%s\', %d, \'%s\', \'%s\',%d,%d, %d, \'%s\', \'%s\',\'%s\',%d, \'%s\', \'%s\', %d,\'%s\')"

#define INSERT_ACCESSAUDIT_LOG(autoid,sip,dip,protocol,sport,dport,application,\
    user,hostname,level,rule,rulehitresult,packetlength,content) do{\
    if(access(AUDIT_SWITCH_FILE, F_OK)!= 0){\
        char sql[4096]={0};\
        snprintf(sql, sizeof(sql), INSERT_ACCESSAUDIT_LOG_FMT, BOARDTYPE_STR, autoid[0],sip,dip,protocol,sport,dport,application,\
    			user,hostname,level,rule,rulehitresult,packetlength,content);\
        insert_into_result(sql, 0, action_insert, NULL); \
		if(RUN_AS_INNER())break;\
		snprintf(sql, sizeof(sql), INSERT_ACCESSAUDIT_LOG_FMT, BOARDTYPE_STR, autoid[1],sip,dip,protocol,sport,dport,application,\
				user,hostname,level,rule,rulehitresult,packetlength,content);\
		insert_into_result(sql, 1, action_insert, NULL); \
    }\
}while(0)

#define INSERT_SESSION_LOG_FMT \
	"insert into "MYSQL_SESSION_TABLE"(boardtype, sessionid, innerifname, outerifname, user, route, state, outerip, outerport, innerip, innerport, protocol,application,recvbytes, sendbytes, recvpackets, sendpackets, recvbps, sendbps, recvpps, sendpps,createdtime) \
	values(\'%s\',%d,\'%s\',\'%s\',\'%s\',\'%s\',\'%d\',\'%s\',%d,\'%s\',%d,%d,\'%s\',%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,\'%s\')"

#define INSERT_SESSION_LOG(sessionid, innerifname, outerifname, user, route, state, outerip, outerport, innerip, innerport,\
		protocol,application,recvbytes, sendbytes, recvpackets, sendpackets, recvbps, sendbps, recvpps, sendpps, createdtime, autoid)\
do{\
	char sql[4096];\
	snprintf(sql, sizeof(sql), INSERT_SESSION_LOG_FMT,\
			BOARDTYPE_STR, sessionid, innerifname, outerifname, user, route, state, outerip, outerport, innerip, innerport, protocol,application,recvbytes, sendbytes, recvpackets, sendpackets, recvbps, sendbps, recvpps, sendpps, createdtime);\
	insert_into_result(sql, 0, action_insert_getid, &autoid[0]); \
	if(RUN_AS_INNER())break;\
	insert_into_result(sql, 1, action_insert_getid, &autoid[1]); \
}while(0)

#define UPDATE_SESSION_LOG_FMT \
	"update "MYSQL_SESSION_TABLE" set application=\'%s\',state=\'%d\', recvbytes=%ld, sendbytes=%ld, recvpackets=%ld, sendpackets=%ld,\
	recvbps=%ld, sendbps=%ld, recvpps=%ld, sendpps=%ld where id=%u"

#define UPDATE_SESSION_LOG(id, proto,state, recvbytes, sendbytes, recvpackets, sendpackets, recvbps, sendbps, recvpps, sendpps)\
do{\
	char sql[4096];\
	snprintf(sql, sizeof(sql), UPDATE_SESSION_LOG_FMT,\
			proto,state, recvbytes, sendbytes, recvpackets, sendpackets, recvbps, sendbps, recvpps, sendpps, id[0]);\
	update_into(sql,0); \
	if(RUN_AS_INNER())break;\
	snprintf(sql, sizeof(sql), UPDATE_SESSION_LOG_FMT,\
			proto,state, recvbytes, sendbytes, recvpackets, sendpackets, recvbps, sendbps, recvpps, sendpps, id[1]);\
	update_into(sql,1); \
}while(0)

int insert_into(char *sql);
int insert_into_result(char *sql, int n, int action, void *arg);
int update_into(char *sql, int n);
void update_session_state(void);
int get_session_by_user(char *username, char *proto);
int print_volume(char *str, int len, int array[]);
char * select_log(struct vty *vty, char *boardtype, const char* table, int offset, int count);
int db_mysql_init(struct thread_master *master);
void db_mysql_exit(void);

/******************************************************
功能：  加载系统数据库配置信息
参数：  无
返回值：正常加载返回1.错误加载返回0。
******************************************************/
int LoadDataBaseConfig();

#endif
