/*********************************************************
* 文件名称:gap_mysql.c
*
* 文件功能:网闸mysql日志数据库
*
* 文件作者:zhangzq
*
* 创建日期:2017-04-27
*
* 修改历史:
	  作者:zhangzq
	  原因:新创建
	  日期:2017-04-27

 *********************************************************/
#include "util-mem.h"
#include <stdio.h>
#include <fcntl.h>

#include <mysql/mysql.h>
#include "app_common.h"
#include "command.h"
#include "list.h"

#include "db_mysql.h"
#include "EMMCJson.h"

#define SQL_LEN 4096
#define FIELD_SPLIT "\t"

//#define CLEANUP_INTERVAL 3600
#define CLEANUP_INTERVAL 10

#define SQL_OPTIMIZE_FMT \
    	"optimize table %s"
#define SQL_CLEANUP_FMT \
		"delete from %s limit %d"
#define SQL_COUNT_FMT \
			"select count(*) from %s"

struct db_mysql_info
{
	struct list_head node;
	char host[24];
	unsigned short port;
	char user[256];
	char passwd[256];
	char database[256];
	MYSQL *mysql;
	pthread_rwlock_t lock;
};
unsigned int get_autoid(struct db_mysql_info * db);

static struct list_head db_handle;
static struct db_mysql_info *information_schema_db;

/*******************************************
*函数名称:execute_sql
*函数功能:执行sql语句的函数接口
*输入参数:
*输出参数:
*返 回 值:无
*修改历史:
	  作者:zhangzq
	  原因:新创建
	  日期:2017-4-27
 ******************************************/
static char* execute_sql(struct db_mysql_info *myinfo, char *sql, int action, char*(*func)(MYSQL_RES *, void *), void *arg)
{
	if (!myinfo) {
		zlog_err("myinfo is NULL\n");
		return NULL;
	}

	if (myinfo->mysql == NULL)
	{
		myinfo->mysql = mysql_init(NULL);
		/* 连接mysql数据库 */
		if (NULL == mysql_real_connect(myinfo->mysql, myinfo->host, myinfo->user, myinfo->passwd, myinfo->database, myinfo->port, NULL, 0)) {
			zlog_err("Failed to connect to database: Error: %s\n", mysql_error(myinfo->mysql));
			mysql_close(myinfo->mysql);
			myinfo->mysql = NULL;
			return NULL;
		}
	}

	if (0 != mysql_real_query(myinfo->mysql, sql, strlen(sql)))
	{
		zlog_err("mysql_real_query foldname Failed(%s)(db=%s), Error: %s\n", sql, myinfo->database, mysql_error(myinfo->mysql));
		mysql_close(myinfo->mysql);
		myinfo->mysql = NULL;
		return NULL;
	}

	if (action == action_select)
	{
		MYSQL_RES *result = NULL;
		if (NULL == (result = mysql_store_result(myinfo->mysql)))
		{
			zlog_err("mysql_store_result foldname failed, Error: %s\n", mysql_error(myinfo->mysql));
			return NULL;
		}

		char*ret = NULL;
		if (func) {
			ret = func(result, arg);
		}
		mysql_free_result(result);
		return ret;
	}
	else if (action == action_insert_getid)
	{
		unsigned int *id = (unsigned int *)arg;
		*id = get_autoid(myinfo);
	}

	return NULL;
}

static char* execute_sql_lock(struct db_mysql_info *myinfo, char *sql, int action, char*(*func)(MYSQL_RES *, void *), void *arg)
{
	char* ret;
	pthread_rwlock_wrlock(&myinfo->lock);
	ret = execute_sql(myinfo, sql, action, func, arg);
	pthread_rwlock_unlock(&myinfo->lock);
	return ret;
}

int insert_into_result(char *sql, int n, int action, void *arg)
{
	struct db_mysql_info * db;
	int i = 0;

	list_for_each_entry(db, &db_handle, node)
	{
		if (i != n) {
			i++;
			continue;
		}
		execute_sql_lock(db, sql, action, NULL, arg);
		break;
	}

	return 0;
}

int insert_into(char *sql)
{
	struct db_mysql_info * db;

	list_for_each_entry(db, &db_handle, node)
	{
		execute_sql_lock(db, sql, action_insert, NULL, NULL);
	}

	return 0;
}

int update_into(char *sql, int n)
{
	struct db_mysql_info * db;
	int i = 0;
	list_for_each_entry(db, &db_handle, node)
	{
		if (i != n) {
			i++;
			continue;
		}
		execute_sql_lock(db, sql, action_insert, NULL, NULL);
		break;
	}

	return 0;
}

char* calc_id(MYSQL_RES *result, void *arg)
{
	unsigned int *id = (int*)arg;

	if (0 != mysql_num_rows(result))
	{
		MYSQL_ROW row;
		if (NULL == (row = mysql_fetch_row(result)))
		{
			zlog_err("mysql_fetch_row foldname failed.");
			return NULL;
		}
		else
		{
			/* 计算容量大小*/
			*id = atol(row[0]);
		}
	}

	return NULL;
}

char* calc_size(MYSQL_RES *result, void *arg)
{
	int *size = (int*)arg;

	if (0 != mysql_num_rows(result))
	{
		MYSQL_ROW row;
		if (NULL == (row = mysql_fetch_row(result)))
		{
			zlog_err("mysql_fetch_row foldname failed.");
			return NULL;
		}
		else
		{
			/* 计算容量大小*/
			*size = atoi(row[0]);
		}
	}

	return NULL;
}

static int audit_off(void)
{
	/* 如果创建了此文件，说明审计功能关闭*/
	if (access("/etc/db_logging_switch", F_OK) == 0) {
		return 1;
	}
	return 0;
}

unsigned int get_autoid(struct db_mysql_info * db)
{
	unsigned int autoid = 0;

	/*获取自增长ID*/
	char sql[SQL_LEN];
	snprintf(sql, sizeof(sql), "SELECT LAST_INSERT_ID()");
	execute_sql(db, sql, action_select, calc_id, &autoid);
	return autoid;
}

int print_volume(char *str, int len, int array[])
{
	int volume_max = DEFAULT_MAX_SIZE;
	int volume_warn = DEFAULT_WARN_SIZE;
	int ret = 0;

	/*获取数据库容量大小*/
	int size = 0;
	char sql[SQL_LEN];
	snprintf(sql, sizeof(sql), "select concat(round(sum(data_length/1024/1024),2),\'\') as data from tables where table_schema=\'gapdb\'");
	execute_sql_lock(information_schema_db, sql, action_select, calc_size, &size);

	/* 如果创建了此文件，说明用户设置了容量阀值*/
	if (access(AUDIT_VOLUME_FILE, F_OK) == 0)
	{
		char buf[128];
		FILE *fp_read = fopen(AUDIT_VOLUME_FILE, "r");
		if (NULL == fp_read) {
			zlog_err("Call fopen() failed.");
			goto out;
		}

		fgets(buf, sizeof(buf) - 1, fp_read);
		fclose(fp_read);
		char *token = strchr(buf, '|');
		volume_max = atoi(buf);
		volume_warn = atoi(token + 1);
	}
out:
	if (size >= volume_warn) 
	{
		ret = 1;
	}
	if (size >= volume_max) 
	{
		ret = 2;
	}
	if (str)
	{
		snprintf(str, len, "\"result\":\"%d\",\"size\":\"%d\",\"limit\":\"%d\",\"alert\":\"%d\"", ret, size, volume_max, volume_warn);
	}
	if (array) 
	{
		array[0] = volume_max;
		array[1] = volume_warn;
		array[2] = size;
	}
	
	return ret;
}

static struct db_mysql_info* init_mysql_db(const char *host, int port,
	const char *username, const char *passwd,
	const char *database)
{
	struct db_mysql_info *db;

	db = SCMalloc(sizeof(struct db_mysql_info));
	if (NULL == db) {
		zlog_err("Call SCMalloc.\n");
		return NULL;
	}

	strncpy(db->host, host, sizeof(db->host));
	strncpy(db->user, username, sizeof(db->user));
	strncpy(db->passwd, passwd, sizeof(db->passwd));
	strncpy(db->database, database, sizeof(db->database));
	db->port = port;
	db->mysql = mysql_init(NULL);
	pthread_rwlock_init(&db->lock, NULL);

	/* 系统数据库 */
	if (NULL == mysql_real_connect(db->mysql, host, username, passwd, database, port, NULL, 0))
	{
		zlog_err("Failed to connect to database: Error: %s\n", mysql_error(db->mysql));
		mysql_close(db->mysql);
		db->mysql = NULL;
	}
	
	//设置数据库默认字符集
	/*if (mysql_set_character_set(db->mysql, "utf8")) 
	{
		fprintf(stderr, "错误, %s/n", mysql_error(&db->mysql));
	}
	
	if (mysql_query(db->mysql, "SET NAMES utf8"))
	{
		fprintf(stderr, "错误, %s/n", mysql_error(&db->mysql));
	}*/

	return db;
}

int init_db(const char *host, int port,
	const char *username, const char *passwd,
	const char *database)
{

	struct db_mysql_info *db = init_mysql_db(host, port, username, passwd, database);

	if (!db)
	{
		return -1;
	}
		
	if (mysql_query(db->mysql, "set names \'utf8\'"))//这个是关键
	{
		fprintf(stderr, "错误, %s/n", mysql_error(&db->mysql));
	}

	list_add_tail(&db->node, &db_handle);
	return 0;
}

void deinit_db(struct db_mysql_info *db)
{
}

/*******************************************
*函数名称:print_record
*函数功能:打印查询到的每一条记录
*输入参数:
*输出参数:
*返 回 值:非空是成功  ，NULL是失败
*修改历史:
	  作者:zhangzq
	  原因:新创建
	  日期:2017-4-27
 ******************************************/
static char* print_record(MYSQL_RES *result, void *arg)
{
	struct vty *vty = (struct vty *)arg;
	/* 获取表的列数  */
	int rows = mysql_num_fields(result);

	/* 获取并输出表头  */
	MYSQL_FIELD *my_field = mysql_fetch_fields(result);
	int i;
	for (i = 0; i < rows; i++)
		vty_out(vty, "%s%s", my_field[i].name, FIELD_SPLIT);
	vty_out(vty, "%s", VTY_NEWLINE);

	/* 输出整个表的内容 */
	while (1) {
		MYSQL_ROW my_row = mysql_fetch_row(result);
		if (NULL == my_row)
			break;
		for (i = 0; i < rows; i++) {
			if (my_row[i] == NULL) {
				vty_out(vty, "NULL%s", FIELD_SPLIT);
			}
			else {
				vty_out(vty, "%s%s", (char*)my_row[i], FIELD_SPLIT);
			}
		}
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	return NULL;
}

/*******************************************
*函数名称:select_log
*函数功能:日志查询接口
*输入参数:
*输出参数:
*返 回 值:0是成功  ，-1是失败
*修改历史:
	  作者:zhangzq
	  原因:新创建
	  日期:2017-4-27
 ******************************************/
char * select_log(struct vty *vty, char *boardtype, const char* table, int offset, int count)
{
	char sql[SQL_LEN];
	snprintf(sql, sizeof(sql), "select * from %s where boardtype = \'%s\' ORDER BY id desc limit %d, %d", table, boardtype, offset, count);

	return execute_sql_lock(list_first_entry_or_null(&db_handle, struct db_mysql_info, node), sql, action_select, print_record, vty);
}

int get_session_by_user(char *username, char *proto)
{
	int count = 0;
	char sql[SQL_LEN];
	snprintf(sql, sizeof(sql), "select count(*) from %s where boardtype = \'%s\' and state != \'4\' and user = \'%s\' and application =\'%s\'", MYSQL_SESSION_TABLE, BOARDTYPE_STR, username, proto);
	execute_sql_lock(list_first_entry_or_null(&db_handle, struct db_mysql_info, node), sql, action_select, calc_size, &count);
	return count;
}

void update_session_state(void)
{
	char sql[SQL_LEN];
	/* 将会话状态更新为:CLOSED */
	snprintf(sql, sizeof(sql), "update %s set state=\'4\' where state != \'4\'", MYSQL_SESSION_TABLE);
	execute_sql_lock(list_first_entry_or_null(&db_handle, struct db_mysql_info, node), sql, action_update, NULL, NULL);
}

int log_cleanup_ontimer(struct thread *t)
{	
	struct thread_master *master = (struct thread_master *)t->arg;
	/*日志已满，保留警戒值大小的日志*/
	char buf[128];
	int size[3] = { 0,0,0 }, ret = 0, trys = 10;
	while (((ret = print_volume(buf, sizeof(buf), size)) == 2) && (trys > 0))
	{
		trys--;
		char *table[] = { MYSQL_OP_TABLE,MYSQL_SYS_TABLE,MYSQL_EVENT_AUDIT_TABLE,
			MYSQL_ACCESS_AUDIT_TABLE,MYSQL_SESSION_TABLE };
		for (int i = 0; i < countof(table); i++) 
		{
			char sql[1024];
			int count = 0;
			/* 获取当前表的记录数目 */
			snprintf(sql, sizeof(sql), SQL_COUNT_FMT, table[i]);
			execute_sql_lock(list_first_entry_or_null(&db_handle, struct db_mysql_info, node), sql, action_select, calc_size, &count);
			/* 释放日志 */
			snprintf(sql, sizeof(sql), SQL_CLEANUP_FMT, table[i], (size[0] - size[1])*count / size[0]);
			execute_sql_lock(list_first_entry_or_null(&db_handle, struct db_mysql_info, node), sql, action_delete, NULL, NULL);
			/* 缩减表大小 */
			snprintf(sql, sizeof(sql), SQL_OPTIMIZE_FMT, table[i]);
			execute_sql_lock(list_first_entry_or_null(&db_handle, struct db_mysql_info, node), sql, action_select, NULL, NULL);
		}
	}

	/* 记录告警日志 */
	if (ret >= 1 || trys != 10) 
	{
		char chLogInfo[200] = { 0 };
		sprintf(chLogInfo, "系统日志占用%dM磁盘空间大于告警阈值%dM,回滚阈值%dM.", size[2], size[1], size[0]);
		
		INSERT_SYS_LOG("Audit", l_critical, chLogInfo);
	}
	thread_add_timer(master, log_cleanup_ontimer, master, CLEANUP_INTERVAL);
	
	return 0;
}

/******************************************************
功能：  加载系统数据库配置信息
参数：  无
返回值：正常加载返回1.错误加载返回0。
******************************************************/
int LoadDataBaseConfig()
{
	int nRetValue = 0;

	FILE* pConfigFp = fopen(DATABASEFILEPATH, "r");
	if (pConfigFp == NULL)
	{
		return 0;
	}

	int nFileLen = 1024;
	struct stat rStat;
	if (lstat(DATABASEFILEPATH, &rStat) == 0)
	{
		nFileLen = rStat.st_size;
	}

	char* pReadString = (char*)malloc(nFileLen);
	fread(pReadString, 1, nFileLen, pConfigFp);

	cJSON* pRoot = cJSON_Parse(pReadString);
	if (pRoot != NULL)
	{
		cJSON* pJsonDBServerIP = cJSON_GetObjectItem(pRoot, "ServerIP");
		cJSON* pJsonDBServerPort = cJSON_GetObjectItem(pRoot, "ServerPort");
		cJSON* pJsonDBName = cJSON_GetObjectItem(pRoot, "DbName");
		cJSON* pJsonDBUsereName = cJSON_GetObjectItem(pRoot, "UserName");
		cJSON* pJsonDBPassword = cJSON_GetObjectItem(pRoot, "Password");

		if ((pJsonDBServerIP != NULL) && (pJsonDBServerPort != NULL) && (pJsonDBName != NULL) && 
			(pJsonDBUsereName != NULL) && (pJsonDBPassword != NULL))
		{
			strncpy(g_rDBConfig.m_chDBServerIP, pJsonDBServerIP->valuestring, sizeof(g_rDBConfig.m_chDBServerIP));
			g_rDBConfig.m_nDBServerPort = Abs(pJsonDBServerPort->valueint);

			strncpy(g_rDBConfig.m_chDBName, pJsonDBName->valuestring, sizeof(g_rDBConfig.m_chDBName));
			strncpy(g_rDBConfig.m_chDBUserName, pJsonDBUsereName->valuestring, sizeof(g_rDBConfig.m_chDBUserName));
			strncpy(g_rDBConfig.m_chDBPassword, pJsonDBPassword->valuestring, sizeof(g_rDBConfig.m_chDBPassword));

			nRetValue = 1;
		}

		cJSON_Delete(pRoot);
	}

	fclose(pConfigFp);

	free(pReadString);
	pReadString = NULL;

	return nRetValue;
}

/*******************************************
*函数名称:db_mysql_init
*函数功能:网闸mysql日志模块初始化接口
*输入参数:
*输出参数:
*返 回 值:0是成功  ，-1是失败
*修改历史:
	  作者:zhangzq
	  原因:新创建
	  日期:2017-4-27
 ******************************************/
int db_mysql_init(struct thread_master *master)
{
	memset(&g_rDBConfig, 0, sizeof(g_rDBConfig));
	
	INIT_LIST_HEAD(&db_handle);
	
	if (LoadDataBaseConfig())
	{
		/* 连接gapdb数据库 */
		if (init_db(g_rDBConfig.m_chDBServerIP, g_rDBConfig.m_nDBServerPort, g_rDBConfig.m_chDBUserName, 
			g_rDBConfig.m_chDBPassword, g_rDBConfig.m_chDBName) < 0) 
		{
			zlog_err("database connect fail.\n");
			return -1;
		}
		
		/* 连接information_schema数据库 */
		information_schema_db = init_mysql_db(g_rDBConfig.m_chDBServerIP, g_rDBConfig.m_nDBServerPort,
			g_rDBConfig.m_chDBUserName, g_rDBConfig.m_chDBPassword, "information_schema");
		if (!information_schema_db) 
		{
			zlog_warn("Call init_db(%d) failed.", SCHEMA_DB);
		}
	}
	else
	{	
		/* 连接gapdb数据库 */
		if (init_db(INNER_DEFAULT_IP_STR, MYSQL_PORT, MYSQL_USERNAME, MYSQL_PASSWD, DATABASE_MYSQL) < 0) 
		{
			zlog_err("database connect fail.\n");
			return -1;
		}

		/* 连接本机information_schema数据库 */
		information_schema_db = init_mysql_db(INNER_DEFAULT_IP_STR, MYSQL_PORT, MYSQL_USERNAME, MYSQL_PASSWD, "information_schema");
		if (!information_schema_db) 
		{
			zlog_warn("Call init_db(%d) failed.", SCHEMA_DB);
		}
	}

	/* 设置日志容量管理定时器 */
	if (master) 
	{
		if (RUN_AS_INNER())
		{
			thread_add_timer(master, log_cleanup_ontimer, master, CLEANUP_INTERVAL);
		}	
	}

	return 0;
}

/*******************************************
*函数名称:gap_mysql_exit
*函数功能:网闸mysql日志模块注销接口
*输入参数:
*输出参数:
*返 回 值:0是成功  ，-1是失败
*修改历史:
	  作者:zhangzq
	  原因:新创建
	  日期:2017-4-27
 ******************************************/
void gap_mysql_exit(void)
{
	struct db_mysql_info *db, *ndb;

	list_for_each_entry_safe(db, ndb, &db_handle, node)
	{
		deinit_db(db);
		list_del(&db->node);
		SCFree(db);
	}
}

