#ifndef _GAP_CMD_DBSYNC_H
#define _GAP_CMD_DBSYNC_H
#include "util-list.h"
#include "gap_cmd.h"

#define TIMER_ID1 1
#define TIMER_ID2 2
#define SYNC_IMAGE_TIME 5
#define DB_INFO_LEN 1024
#define TABLE_MAX_NUM 128
#define FIELD_MAX_NUM 32
#define FIELD_LEN 128
#define BUFF_SIZE 1024

#define INI_GROUP_NAME_LEN 128
#define IP_LEN 36
#define DB_INSTANCE_LEN 128
#define TIME_OUT_LEN 20
#define CLI_CHARSET 36
#define DUMP_FILE_LEN 128
#define VERSION_LEN 36



enum dbsync_task_state
{

	task_stop,
	task_start

};

enum dbsync_init_state
{
	init_failed,
	init_success
};

enum dbsync_dir
{
	src_to_dst,
	dst_to_src
};

enum db_net
{
	in_net,
	out_net
};

enum
{
	ordinary_mode,
	timer_mode
};

enum dbsync_type
{
	increment_type,
	image_type
};


struct sql_ini_config
{
	char sql_version[VERSION_LEN];

	char src_ini_groupname[INI_GROUP_NAME_LEN];//title
	char src_ip[IP_LEN];//ip
	char src_port[PORT_LEN];//port
	char src_instance[DB_INSTANCE_LEN];//数据库实例
	char src_time_out[TIME_OUT_LEN];
	char src_cli_charset[CLI_CHARSET];//UTF-8
	char src_dump_file[DUMP_FILE_LEN];//log


	char dst_ini_groupname[INI_GROUP_NAME_LEN];//title
	char dst_ip[IP_LEN];//ip
	char dst_port[PORT_LEN];//port
	char dst_instance[DB_INSTANCE_LEN];//数据库实例
	char dst_time_out[TIME_OUT_LEN];
	char dst_cli_charset[CLI_CHARSET];//UTF-8
	char dst_dump_file[DUMP_FILE_LEN];//log
};

enum {
	DB_SRC = 0,
	DB_DEST,
	DB_INFO_MAX
};
enum {
	DB_TYPE_FREETDS = 0,
	DB_TYPE_MYSQL,
	DB_TYPE_ORCALE
};

#define DB_TYPE_STRING(x) \
    ((x)==DB_TYPE_FREETDS?"freetds":(((x)==DB_TYPE_MYSQL)?"mysql":(((x)==DB_TYPE_ORCALE?"orcale":"unkown"))))
struct db_info {
	int location; /* inner net or extenal net */
	const char* db_type;  /* freetds,mysql,... */
	const char *host;  /* db server  ip address */
	int port; /*db srever port ,such as 1433,3066*/
	const char *username; /* db username */
	const char *password; /*  db user password */
	const char *instance; /* db name */
};

#define DB_SYNC_OPERATIONS_UPDATE 1
#define DB_SYNC_OPERATIONS_INSERT 2
#define DB_SYNC_OPERATIONS_DELETE 4

struct dbsync_mode {
	int interval_mode; /* interval or timmer */
	int intervals; /* seconds */
	int sync_mode; /* increase or image */
	int sync_direction; /* single direction or double direction */
	int sync_conflict_deal; /* data conflict, 0 cover, 1-ignore */
	int sync_operations;/* UPDATE, INSERT, DELETE */
};
struct dbsync_task
{
	struct list_head n_list;
	/* task info */
	char name[NAME_LEN + 1];//数据库同步任务的名称
	char *description;//任务描述
	int state;//任务状态:启动或停止
	int init_state;//初始化远程数据库配置状态，包括创建触发器、临时表等等

	/* DB info */
	struct db_info db_info[DB_INFO_MAX];

	/* config */
	struct dbsync_mode sync_mode;

	char workdir[256];
	char configfile[256];/* json formt config file */
	struct json_object *jobj;//前台配置的参数转化成json格式
	struct thread *timer;
	SCMutex lock;

};

struct dbsync_timer
{
	struct list_head n_list;
	int id; //定义器ID，每个同步任务最多有2个定时器。取值1和2
	int interval;//任务执行间隔时间
	int syncdir;//同步方向，0: 源->目的，1: 目的->源

	struct thread *thread;
	struct dbsync_task *task;
};
struct thread * dbsync_add_timer(int(*func) (struct thread *), void *arg, long interval);

#endif 
