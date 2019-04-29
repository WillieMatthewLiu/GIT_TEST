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
#include "gap_cmd_dbsync.h"
#include "json-c.h"
#include "dbsynctask.h"
#include <glib.h>
#include "db_mysql.h"
#include "rsync.h"

/**********************************************************************************************************************
DB sync config format

{
	u'dbInfo':{
		u'name': u'dbconfig',
		u'description': u'db sync for database xxx',
		u'source': 	{
			u'port': u'1433',
			u'location': u'0',
			u'instance': u'test',
			u'type': u'freetds',
			u'password': u'123456',
			u'username': u'hello',
			u'host': u'192.168.40.211'
		},

		u' destination': {
			u'port': u'1433',
			u'location': u'1',
			u'instance': u'test',
			u'type': u'freetds',
			u'password': u'123456',
			u'username': u'hello',
			u'host': u'192.168.40.211'
		},
		u'synConfig': {
				u'interval_mode': u'0',
				u'intervals': u'60',
				u'syn_mode': u'0',
				u'sync_dirrection': u'0',
				u'sync_conflict_deal': u'0',
				u'sync_operations': [u'update','insert','delete'],
			}

	},
  u'synCondition': {
	u'srcdb':{
		'tables':{ [
		{
			u'fields':[u'id|int(4)|N|Y', u'name|nchar(20)|N|N', u'age|nchar(20)|N|N'],
			u'name': u'Table_1',
			u'key': u'id|int(4)|N|Y
		}
		]}
	},
	u'dstdb': {
		'tables':{[
		{
			u'fields': [u'id|int(4)|N|Y', u'name|nchar(20)|N|N', u'age|nchar(20)|N|N'],
			u'name': u'Table_1', u'key': u'id|int(4)|N|Y'
		}]
		   }
	}
  },

}
***********************************************************************************************************************/

#define DB_SYNC_WORK_DIR "/var/run/dbsync"
#define DB_SYNC_JSON_CONF "config.json"
#define DB_SYNC_RSYNC_PREF "dbsync"
#define DB_SYNC_CONFIG_MAX 10

static int _db_sync_task_active_num = 0;
static struct dbsync_task _db_sync_task[DB_SYNC_CONFIG_MAX];
static struct list_head _db_sync_task_head = LIST_HEAD_INIT(_db_sync_task_head);


#define  SQL_CONFIG_FILE_PATH "/etc/freetds.conf"
#define FREETDS_CONFIG_PREF "rongan_sqlserver_"

static int create_freedts_config(const char *taskname, const char *src_dest, struct db_info *dbinfo)
{
	GKeyFile *keyfile;
	GKeyFileFlags flags;
	GError *error = NULL;
	char section[128];

	keyfile = g_key_file_new();
	//flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
	flags = G_KEY_FILE_NONE;
	if (!g_key_file_load_from_file(keyfile, SQL_CONFIG_FILE_PATH, flags, &error))
	{
		g_error(error->message);
		return -1;
	}

	snprintf(section, 128, "%s_%s", taskname, src_dest);


	//设置新值之前先删除
	g_key_file_remove_group(keyfile, section, NULL);


	g_key_file_set_value(keyfile, section, "host", dbinfo->host);
	g_key_file_set_integer(keyfile, section, "port", dbinfo->port);
	g_key_file_set_value(keyfile, section, "instance", dbinfo->instance);
	g_key_file_set_value(keyfile, section, "username", dbinfo->username);
	g_key_file_set_value(keyfile, section, "password", dbinfo->password);


	g_key_file_set_value(keyfile, section, "tds version", "7.1");

	g_key_file_save_to_file(keyfile, SQL_CONFIG_FILE_PATH, &error);

	g_key_file_free(keyfile);
	return 0;

}

static int delete_freedts_config(const char *taskname, const char *src_dest, struct db_info *dbinfo) 
{
	GKeyFile *keyfile;
	GKeyFileFlags flags;
	GError *error = NULL;
	char section[128];

	keyfile = g_key_file_new();
	//flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
	flags = G_KEY_FILE_NONE;
	if (!g_key_file_load_from_file(keyfile, SQL_CONFIG_FILE_PATH, flags, &error))
	{
		g_error(error->message);
		return -1;
	}
	snprintf(section, 128, FREETDS_CONFIG_PREF "%s_%s", taskname, src_dest);

	g_key_file_remove_group(keyfile, section, NULL);

	g_key_file_save_to_file(keyfile, SQL_CONFIG_FILE_PATH, &error);
	g_key_file_free(keyfile);
	return 0;
}

static int create_db_rsync_config(const struct dbsync_task* task)
{
	struct rsync_module_parameters param = { 0 };
	char group[128] = { 0 };
	char path[128] = { 0 };
	char secrets_file[128] = { 0 };

	snprintf(group, 128, "%s_%s", DB_SYNC_RSYNC_PREF, task->name);
	snprintf(path, 128, "%s/%s", DB_SYNC_WORK_DIR, task->name);
	snprintf(secrets_file, 128, "%s/%s.secrets", task->workdir, task->name);

	param.name = group;
	param.path = path;
	param.read_only = 0;
	param.list = 1;
	param.uid = "root";
	param.gid = "root";
	param.auth_users = task->name;
	param.secrets_file = secrets_file;
	if (task->db_info[DB_DEST].location == board_type)
	{
		cmd_system_novty_arg("echo '%s:%s' > %s", task->name, task->name, secrets_file);
	}
	else
	{
		cmd_system_novty_arg("echo '%s' > %s", task->name, secrets_file);
	}

	rsync_write_module(RSYNC_CONFIG_PATH, &param);

	return 0;
}

static void delete_db_rsync_config(const struct dbsync_task* task) 
{
	rsync_remove_module(RSYNC_CONFIG_PATH, task->name);
}

static struct dbsync_task* dbsync_task_new(const char* name) 
{
	int i = 0;
	struct dbsync_task* task = _db_sync_task;

	for (i = 0; i < DB_SYNC_CONFIG_MAX; i++, task++) 
	{
		if (task->name[0] == '\0')
		{
			strcpy(task->name, name);
			task->name[NAME_LEN] = '\0';
			return task;
		}
	}

	return NULL;

}

static void dbsync_task_free(struct dbsync_task* task) 
{
	int i;
	struct db_info* dbinfo = NULL;
	memset(task->name, 0, NAME_LEN);

	task->state = task_stop;
	task->init_state = 0;

	if (task->description)
	{
		SCFree(task->description);
	}
	task->description = NULL;

	for (i = 0; i < DB_INFO_MAX; i++)
	{
		dbinfo = &task->db_info[i];

		if (dbinfo->db_type)
			SCFree(dbinfo->db_type);
		if (dbinfo->host)
			SCFree(dbinfo->host);
		if (dbinfo->username)
			SCFree(dbinfo->username);
		if (dbinfo->password)
			SCFree(dbinfo->password);
		if (dbinfo->instance)
			SCFree(dbinfo->instance);

		memset(dbinfo, 0, sizeof(struct db_info));
	}

	remove(task->workdir);

	if (task->jobj)
	{
		json_object_put(task->jobj);
	}
	task->jobj = NULL;
}

struct dbsync_task* dbsync_task_lookup_by_name(const char* name) 
{
	struct dbsync_task *task;

	list_for_each_entry(task, &_db_sync_task_head, n_list)
	{
		if ((0 == strncmp(name, task->name, NAME_LEN))) 
		{
			return task;
		}
	}

	return NULL;
}

static int calc_distance(int interval)
{
	time_t now = time(NULL);
	struct tm now_tm;
	localtime_r(&now, &now_tm);
	int start = now_tm.tm_hour * 3600 + now_tm.tm_min * 60;
	int distance = interval - start;
	if (distance < 0)
	{
		distance += 86400 - interval;
	}

	return distance;
}

static void run_start(struct dbsync_task* task)
{
	task->init_state = !cmd_system_novty_arg("python /var/www/dbsync.py -t %s -c %s -a start",
		task->name, task->configfile);

	insert_sys_log("数据库同步", l_warn, "数据库同步任务 %s 开始执行", task->name);
}

static void run_stop(struct dbsync_task *task) 
{
	task->init_state = cmd_system_novty_arg("python /var/www/dbsync.py -t %s -c %s -a stop",
		task->name, task->configfile);
	insert_sys_log("数据库同步", l_warn, "数据库同步任务 %s 中止执行", task->name);
}

static void run_export(struct dbsync_task *task) 
{
	cmd_system_novty_arg("python /var/www/dbsync.py -t %s -s %s -c %s -a export",
		task->name, "source", task->configfile);

	insert_sys_log("数据库同步", l_info, "数据库同步任务 %s 导出", task->name);
}

static void run_push(struct dbsync_task *task)
{
	cmd_system_novty_arg("cd %s && rsync --remove-source-files *.sql %s@%s::%s_%s --password-file=%s/%s.secrets",
		task->workdir,
		task->name, RUN_AS_INNER() ? OUTER_DEFAULT_IP_STR : INNER_DEFAULT_IP_STR,
		DB_SYNC_RSYNC_PREF, task->name,
		task->workdir, task->name);

	insert_sys_log("数据库同步", l_info, "数据库同步任务 %s 生成", task->name);
}

static void run_import(struct dbsync_task *task) 
{
	cmd_system_novty_arg("python /var/www/dbsync.py -t %s -s %s -c %s -a import",
		task->name, "destination", task->configfile);
	insert_sys_log("数据库同步", l_info, "数据库同步任务 %s 导入", task->name);
}

static int dbsync_handle(struct thread *t)
{
	int handle_ok = 0;
	struct dbsync_task* task = (struct dbsync_task *)THREAD_ARG(t);
	if (!task)
	{
		return 0;
	}

	SCMutexLock(&task->lock);
	task->timer = NULL;

	switch (task->state)
	{
	case task_start:
	{
		insert_sys_log("数据库同步", l_info, "数据库同步任务 %s 正在执行", task->name);
		/* if source db and we at the same side, run export database change */
		if (task->db_info[DB_SRC].location == board_type)
		{
			run_export(task);
			if (task->db_info[DB_SRC].location != task->db_info[DB_DEST].location) 
			{
				/* push file to partner */
				run_push(task);
			}
		}
		else 
		{
			/* we run export on parnter */
		}

		if (task->db_info[DB_DEST].location == board_type) 
		{
			run_import(task);
		}


		/* uf dest db and we at the same side, run import database change */

		/* 再次加入定时器 */
		/* maybe need adjust timer */
		{
			int interval;
			if (ordinary_mode == task->sync_mode.interval_mode) 
			{
				interval = task->sync_mode.intervals;
			}
			else 
			{
				interval = calc_distance(task->sync_mode.intervals);
			}
			task->timer = dbsync_add_timer(dbsync_handle, task, interval);
		}

	}
	break;

	default:
		break;
	}

	SCMutexUnlock(&task->lock);

	return handle_ok;
}

static void dbsynctimer_start(struct dbsync_task *task)
{
	long interval;
	if (ordinary_mode == task->sync_mode.interval_mode)
	{
		interval = task->sync_mode.intervals;
	}
	else 
	{
		interval = calc_distance(task->sync_mode.intervals);
	}

	if (task->db_info[DB_SRC].location == board_type || task->db_info[DB_DEST].location == board_type)
	{
		task->timer = dbsync_add_timer(dbsync_handle, task, interval);
	}

}

static int convert_dbinfo(struct db_info *db_info, struct json_object *jobj)
{
	json_object_object_foreach(jobj, key, sjobj) 
	{
		if (strcmp(key, "type") == 0)
		{
			db_info->db_type = SCStrdup(json_object_get_string(sjobj));
		}
		else if (strcmp(key, "location") == 0)
		{
			db_info->location = json_object_get_int(sjobj);
		}
		else if (strcmp(key, "host") == 0) 
		{
			db_info->host = SCStrdup(json_object_get_string(sjobj));
		}
		else if (strcmp(key, "port") == 0)
		{
			db_info->port = json_object_get_int(sjobj);
		}
		else if (strcmp(key, "username") == 0) 
		{
			db_info->username = SCStrdup(json_object_get_string(sjobj));
		}
		else if (strcmp(key, "password") == 0)
		{
			db_info->password = SCStrdup(json_object_get_string(sjobj));
		}
		else if (strcmp(key, "instance") == 0)
		{
			db_info->instance = SCStrdup(json_object_get_string(sjobj));
		}
		else
		{
		}
	}

	return 0;
}

static int convert_sync_mode(struct dbsync_mode *m, struct json_object *jobj) 
{
	json_object_object_foreach(jobj, key, sjobj) 
	{
		if (strcmp(key, "interval_mode") == 0) 
		{
			m->interval_mode = json_object_get_int(sjobj);
		}
		else if (strcmp(key, "intervals") == 0)
		{
			m->intervals = json_object_get_int(sjobj);
		}
		else if (strcmp(key, "sync_mode") == 0)
		{
			m->sync_mode = json_object_get_int(sjobj);
		}
		else if (strcmp(key, "sync_direction") == 0)
		{
			m->sync_direction = json_object_get_int(sjobj);
		}
		else if (strcmp(key, "sync_conflict_deal") == 0)
		{
			m->sync_conflict_deal = json_object_get_int(sjobj);
		}
		else if (strcmp(key, "sync_operations") == 0)
		{
			int  i;
			for (i = 0; i < json_object_array_length(sjobj); i++) 
			{
				const char *op = json_object_get_string(json_object_array_get_idx(sjobj, i));
				if (!op)
				{
					continue;
				}

				switch (op[0]) 
				{
				case 'u':
					m->sync_operations += 1; break;
				case 'i':
					m->sync_operations += 2; break;
				case 'd':
					m->sync_operations += 4; break;

				default:break;
				}
			}
		}
		else 
		{
		}
	}
	return 0;
}

static struct json_object* dbsync_condition_new() 
{
	struct json_object *jobj = json_object_new_object();
	json_object_object_add(jobj, "source", json_object_new_object());
	json_object_object_add(jobj, "destination", json_object_new_object());

	json_object_object_foreach(jobj, key, val)
	{
		json_object_object_add(val, "tables", json_object_new_array());
	}

	return jobj;
}

static int dbsync_add_json_config(struct dbsync_task *task, struct json_object *jobj)
{
	if (task->jobj)
	{
		json_object_put(task->jobj);
	}
	task->jobj = json_object_new_object();
	json_object_object_add(task->jobj, "dbInfo", jobj);
	json_object_object_add(task->jobj, "synCondition", dbsync_condition_new());

	json_object_object_foreach(jobj, key, sjobj) 
	{
		if (strcmp("source", key) == 0) 
		{
			convert_dbinfo(&task->db_info[DB_SRC], sjobj);
			if (strcmp(task->db_info[DB_SRC].db_type, "freetds") == 0)
			{
				create_freedts_config(task->name, key, &task->db_info[DB_SRC]);
			}
		}
		else if (strcmp("destination", key) == 0)
		{
			convert_dbinfo(&task->db_info[DB_DEST], sjobj);
			if (strcmp(task->db_info[DB_DEST].db_type, "freetds") == 0) 
			{
				create_freedts_config(task->name, key, &task->db_info[DB_DEST]);
			}
		}
		else if (strcmp("sync_mode", key) == 0) 
		{
			convert_sync_mode(&task->sync_mode, sjobj);
		}
		else if (strcmp("description", key) == 0) 
		{
			task->description = SCStrdup(json_object_get_string(sjobj));
		}
		else if (strcmp("name", key) == 0) 
		{

		}
		else 
		{
			fprintf(stderr, "Unknown key %s\n", key);
		}
	}

	return 0;

}

DEFUN(gap_ctl_dbsync_add,
	gap_ctl_dbsync_add_cmd,
	"db sync add .JSON",
	"database module\n"
	"sync\n"
	"add a new task\n"
	"json format string\n")
{
	if (_db_sync_task_active_num >= DB_SYNC_CONFIG_MAX)
	{
		vty_out(vty, "no enough resource to create task.%s", VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	CONFIG_SYNC_CMD();

	const char* taskname;
	struct dbsync_task* task;
	struct json_object* sobj = NULL;
	enum json_tokener_error error;

	struct json_object* jobj = json_tokener_parse_verbose(argv[0], &error);
	if (jobj == NULL || json_tokener_success != error) 
	{
		vty_out(vty, "%s%s", json_tokener_error_desc(error), VTY_NEWLINE);
		vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	if (!json_object_object_get_ex(jobj, "name", &sobj))
	{
		vty_out(vty, "not found task name.%s", VTY_NEWLINE);
		json_object_put(jobj);
		return CMD_ERR_NOTHING_TODO;
	}

	taskname = json_object_get_string(sobj);
	if (taskname == NULL) 
	{
		vty_out(vty, "not found task name.%s", VTY_NEWLINE);
		json_object_put(jobj);
		return CMD_ERR_NOTHING_TODO;
	}

	task = dbsync_task_lookup_by_name(taskname);
	if (task != NULL)
	{
		vty_out(vty, "task %s is exist%s", taskname, VTY_NEWLINE);
		json_object_put(jobj);
		return CMD_ERR_NOTHING_TODO;
	}

	task = dbsync_task_new(taskname);

	dbsync_add_json_config(task, jobj);

	/* create rsync dirs for sql file push */
	snprintf(task->workdir, 256 - 1, "%s/%s", DB_SYNC_WORK_DIR, task->name);
	snprintf(task->configfile, 256 - 1, "%s/%s/%s", DB_SYNC_WORK_DIR, task->name, DB_SYNC_JSON_CONF);

	mkdir(task->workdir, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	json_object_to_file(task->configfile, task->jobj);

	create_db_rsync_config(task);

	list_add(&task->n_list, &_db_sync_task_head);
	_db_sync_task_active_num++;

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_dbsync_edit,
	gap_ctl_dbsync_edit_cmd,
	"db sync edit .JSON",
	"database module\n"
	"sync\n"
	"edit a new task\n"
	"json format string\n")
{
	int err;
	const char *taskname;
	struct dbsync_task *task;
	struct json_object *sobj;
	struct json_object *jobj = json_tokener_parse(argv[0]);

	if (jobj == NULL) 
	{
		vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	CONFIG_SYNC_CMD();

	if (!json_object_object_get_ex(jobj, "name", &sobj)) 
	{
		vty_out(vty, "not found task name.%s", VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	taskname = json_object_get_string(sobj);
	if (taskname == NULL) 
	{
		vty_out(vty, "not found task name.%s", VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	task = dbsync_task_lookup_by_name(taskname);
	if (task == NULL) 
	{
		/* we will add a new task */
		vty_out(vty, "task %s not found.%s", taskname, VTY_NEWLINE);
		return ERR_CODE_NOTFOUND;
	}
	if (task->state == task_start)
	{
		vty_out(vty, "task %s is busy, try again later.%s", taskname, VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	err = SCMutexTrylock(&task->lock);

	if (err == EBUSY)
	{
		vty_out(vty, "task %s is busy, try again later.%s", taskname, VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	dbsync_add_json_config(task, jobj);
	json_object_to_file(task->configfile, task->jobj);
	SCMutexUnlock(&task->lock);

	return CMD_SUCCESS;
}


DEFUN(gap_ctl_dbsync_add_tables,
	gap_ctl_dbsync_add_tables_cmd,
	"db sync NAME add (source| destination) tables .JSON",
	"database module\n"
	"sync\n"
	"taskname\n"
	"add a new task\n"
	"json format string\n")
{
	int i;
	const char *table_name = NULL;
	struct dbsync_task *task;
	struct json_object *jsyncCond, *tmp;

	struct json_object *jobj = json_tokener_parse(argv[2]);
	if (jobj == NULL) 
	{
		vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
		json_object_put(jobj);
		return CMD_ERR_NOTHING_TODO;
	}

	if (!json_object_object_get_ex(jobj, "name", &tmp))
	{
		vty_out("not found name key.%s", VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}
	table_name = json_object_get_string(tmp);
	
	CONFIG_SYNC_CMD();

	task = dbsync_task_lookup_by_name(argv[0]);
	if (task == NULL) 
	{
		vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
		json_object_put(jobj);
		return ERR_CODE_EXIST;
	}

	if (task->state == task_start)
	{
		return CMD_ERR_NOTHING_TODO;
	}

	if (!json_object_object_get_ex(task->jobj, "synCondition", &jsyncCond)) 
	{
		json_object_put(jobj);
		return CMD_ERR_NOTHING_TODO;
	}

	json_object_object_foreach(jsyncCond, key, val) 
	{
		if (strcmp(key, argv[1]) == 0)
		{
			json_object_object_foreach(val, key2, val2) 
			{
				for (i = 0; i < json_object_array_length(val2); i++) 
				{
					struct json_object *table;
					if (json_object_object_get_ex(json_object_array_get_idx(val2, i), "name", &table))
					{
						if (strcmp(table_name, json_object_get_string(table)) == 0)
						{
							/* found a exist table, ignore it */
							break;
						}
					}
				}
				if (i >= json_object_array_length(val2))
					json_object_array_add(val2, jobj);
			}
		}
	}

	unlink(task->configfile);
	json_object_to_file(task->configfile, task->jobj);

	return CMD_SUCCESS;
}


DEFUN(gap_ctl_dbsync_change_state,
	gap_ctl_dbsync_change_state_cmd,
	"db sync (enable|disable) NAME",
	"database module\n"
	"sync\n"
	"enable a task\n"
	"disable a task\n"
	"task name\n")
{
	CONFIG_SYNC_CMD();

	int err;

	struct dbsync_task *task = dbsync_task_lookup_by_name(argv[1]);
	if (task == NULL)
	{
		return CMD_ERR_NOTHING_TODO;
	}

	if (task->db_info[DB_SRC].location != board_type
		&& task->db_info[DB_DEST].location != board_type) 
	{
		return CMD_ERR_NOTHING_TODO;
	}
	err = SCMutexLock(&task->lock);

	if (err == EBUSY)
	{
		vty_out(vty, "task %s is busy, try again later.%s", task->name, VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}
	
	/* runing it or disable it  */
	switch (argv[0][0])
	{
	case 'e':
		if (task->state == task_start)
		{
			break;
		}
		/* tell task process to create trigger */
		run_start(task);
		/* start task */
		dbsynctimer_start(task);
		task->state = task_start;
		break;

	case 'd':
		if (task->state == task_stop)
		{
			break;
		}

		/* tell task process to destroy trigger */
		run_stop(task);
		/* stop task */
		if (task->timer)
		{
			thread_cancel(task->timer);
		}
		task->timer = NULL;
		task->state = task_stop;

	default:
		break;
	}

	SCMutexUnlock(&task->lock);

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_no_dbsynctask,
	gap_ctl_no_dbsynctask_cmd,
	"no db sync name WORD",
	"no command\n"
	"delete dbsynctask\n"
	"dbsynctask's name\n"
	"dbsynctask's name\n")
{
	const char *taskname = argv[0];

	/*  delete task at outer*/
	CONFIG_SYNC_CMD();

	struct dbsync_task* task = dbsync_task_lookup_by_name(taskname);
	if (!task)
	{
		return CMD_ERR_NOTHING_TODO;
	}

	if (task->state == task_stop) 
	{
		if (task->timer)
		{
			thread_cancel(task->timer);
		}
	}
	else
	{
		vty_out(vty, "task %s is busy, try again later%s", taskname, VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	list_del_init(&task->n_list);
	delete_db_rsync_config(task);
	dbsync_task_free(task);

	_db_sync_task_active_num--;

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_show_dbsynctask,
	gap_ctl_show_dbsynctask_cmd,
	"show db sync all",
	SHOW_STR
	"show dbsynctask\n"
	"all config\n")
{
	struct dbsync_task *task;

	SHOW_CMD_RUN();

	list_for_each_entry(task, &_db_sync_task_head, n_list) 
	{
		vty_out(vty, "%s %s %d %d%s", task->name, task->description, task->state, task->init_state, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


ALIAS(gap_ctl_show_dbsynctask,
	gap_ctl_show_dbsynctask_o_cmd,
	"show outer db sync all",
	SHOW_STR
	"outer machine\n"
	"show dbsynctask\n"
	"all config\n")

DEFUN(gap_ctl_show_dbsynctask_by_name,
	gap_ctl_show_dbsynctask_by_name_cmd,
	"show db sync name WORD",
	SHOW_STR
	"show dbsynctask\n"
	"dbsynctask's name\n"
	"dbsynctask's name, such as:task1\n")
{
	struct dbsync_task *task;
	SHOW_CMD_RUN();

	task = dbsync_task_lookup_by_name(argv[0]);
	if (task && task->jobj)
	{
		vty_out(vty, "%s%s", JSON_FORMAT_STR_PLAIN(task->jobj), VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_show_dbsynctask_by_name,
	gap_ctl_show_dbsynctask_by_name_o_cmd,
	"show outer db sync name WORD",
	SHOW_STR
	"outer machine\n"
	"show dbsynctask\n"
	"dbsynctask's name\n"
	"dbsynctask's name, such as:task1\n");


int test_db(struct vty *vty,
	const char*taskname,
	const char *src_dest,
	const char *workdir,
	const char *configfile,
	const struct db_info *db_info)
{
	int i;
	char result_file[256] = { 0 };
	snprintf(result_file, 256, "%s/dbinfo_%s_%s.json", workdir, taskname, src_dest);

	unlink(result_file);
	cmd_system_novty_arg("python /var/www/dbsync.py -t %s -s %s -c %s -a test",
		taskname, src_dest, configfile);

	for (i = 0; i < 100; i++)
	{
		struct json_object *jobj;

		if (access(result_file, F_OK) < 0)
		{
			usleep(100);
			continue;
		}

		jobj = json_object_from_file(result_file);
		if (jobj)
		{
			vty_out(vty, "%s%s", JSON_FORMAT_STR_PLAIN(jobj), VTY_NEWLINE);
			return CMD_SUCCESS;
		}
		else
		{
			vty_out(vty, "error%s", VTY_NEWLINE);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_test_dbsynctask,
	gap_ctl_test_dbsynctask_cmd,
	"test db sync (source| destination) .JSON",
	"test command\n"
	"test dbsynctask\n"
	"source database\n"
	"destination database\n"
	"json parameter, such as:{'dbInfo':{'name':,.....}\n")
{
	int ret;
	char workdir[128] = { 0 };
	char dbsync_conf_file[128] = { 0 };
	const char *taskname = NULL;
	struct db_info db_info = { 0 };
	enum json_tokener_error error;
	struct json_object *jobj = json_tokener_parse_verbose(argv[1], &error);
	if (!jobj)
	{
		SCLogError("json parser error %d\n", error);
		vty_out(vty, "%s%s", ERR_CODE_JSONERR_DESC, VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	CONF_CMD_RUN();
	json_object_object_foreach(jobj, key, sobj)
	{
		json_object_object_foreach(sobj, key2, val)
		{
			if (strcmp(key2, "name") == 0) 
			{
				taskname = json_object_get_string(val);
				break;
			}
			else if (strcmp(key2, argv[0]) == 0)
			{
				convert_dbinfo(&db_info, val);
			}
		}
	}
	if (taskname == NULL)
	{
		vty_out(vty, "no task name set.%s", VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	snprintf(workdir, 128, "%s/%s", DB_SYNC_WORK_DIR, taskname);
	mkdir(workdir, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	/* now we write all db info to config file */
	snprintf(dbsync_conf_file, 128, "%s/%s/%s", DB_SYNC_WORK_DIR, taskname, DB_SYNC_JSON_CONF);
	json_object_to_file(dbsync_conf_file, jobj);

	/* if db type is freetds, write /etc/freetds.conf */
	if (strcmp(db_info.db_type, "freetds") == 0) 
	{
		create_freedts_config(taskname, argv[0], &db_info);
	}

	ret = test_db(vty, taskname, argv[0], workdir, dbsync_conf_file, &db_info);
	if (CMD_SUCCESS != ret)
	{
		if (strcmp(db_info.db_type, "freetds") == 0)
		{
			delete_freedts_config(taskname, argv[0], &db_info);
		}

		rmdir(workdir);
	}

	json_object_put(jobj);

	return ret;
}

ALIAS(gap_ctl_test_dbsynctask,
	gap_ctl_test_dbsynctask_o_cmd,
	"outer test db sync (source| destination) .JSON",
	"outer machine\n"
	"test command\n"
	"dbsync task\n"
	"source\n"
	"destination\n"
	"json parameter, such as:{'dbInfo':{'name':,.....}\n");

int dbsync_write_conf(struct vty *vty)
{
	int i;
	int count;
	struct json_object *jobj;
	struct dbsync_task *task;
	for (task = _db_sync_task, i = 0; i < DB_SYNC_CONFIG_MAX; i++, task++)
	{
		if (NULL == task->jobj)
		{
			continue;
		}

		if (!json_object_object_get_ex(task->jobj, "dbInfo", &jobj)) 
		{
			continue;
		}

		vty_out(vty, "db sync add %s%s",
			JSON_FORMAT_STR_PLAIN(jobj),
			VTY_NEWLINE);
		count++;

		if (!json_object_object_get_ex(task->jobj, "synCondition", &jobj)) 
		{
			continue;
		}

		json_object_object_foreach(jobj, key, ssobj)
		{
			json_object_object_foreach(ssobj, key2, tables)
			{
				int i = 0;
				for (i = 0; i < json_object_array_length(tables); i++)
				{
					vty_out(vty, "db sync %s add %s %s %s%s",
						task->name, key, key2,
						JSON_FORMAT_STR_PLAIN(json_object_array_get_idx(tables, i)),
						VTY_NEWLINE);
				}
				count++;
			}
		}

		if (task->state == task_start) 
		{
			vty_out(vty, "db sync enable %s%s", task->name, VTY_NEWLINE);
			count++;
		}
	}

	return count;
}

static struct cmd_node dbsync_node =
{
	.node = DB_SYNC_NODE,
	.prompt = "",
	.vtysh = 1
};

static void dbsync_conf_cmd_init(void)
{
	install_node(&dbsync_node, dbsync_write_conf);
	install_element(CONFIG_NODE, &gap_ctl_no_dbsynctask_cmd);
	install_element(CONFIG_NODE, &gap_ctl_test_dbsynctask_cmd);
	install_element(CONFIG_NODE, &gap_ctl_test_dbsynctask_o_cmd);

	install_element(CONFIG_NODE, &gap_ctl_dbsync_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_dbsync_edit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_dbsync_add_tables_cmd);
	install_element(CONFIG_NODE, &gap_ctl_dbsync_change_state_cmd);
}

static void dbsync_show_cmd_init()
{
	install_element(VIEW_NODE, &gap_ctl_show_dbsynctask_o_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_dbsynctask_o_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_dbsynctask_by_name_o_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_dbsynctask_by_name_o_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_dbsynctask_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_dbsynctask_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_dbsynctask_by_name_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_dbsynctask_by_name_cmd);
}

void dbsync_init(void)
{
	int i;
	struct dbsync_task *task = _db_sync_task;

	for (i = 0; i < DB_SYNC_CONFIG_MAX; i++, task++) 
	{
		memset(task, 0, sizeof(struct dbsync_task));
		SCMutexInit(&task->lock, NULL);
	}

	mkdir(DB_SYNC_WORK_DIR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	dbsync_conf_cmd_init();
	dbsync_show_cmd_init();
}

void dbsync_exit(void)
{
	int i;
	struct dbsync_task* task = _db_sync_task;

	for (i = 0; i < DB_SYNC_CONFIG_MAX; i++, task++) 
	{
		dbsync_task_free(task);
		SCMutexDestroy(&task->lock);
	}
}