
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
#include "gap_ctl_ha.h"
#include "gap_ctl_adapter.h"

#include "gap_ctl.h"
#include "gap_cmd_report.h"
#include "json-c.h"

static struct email_periodic_report epr;
static struct email_timely_alarm eta;
static pthread_rwlock_t report_lock;
static struct thread_master *g_report_master;
static pthread_t g_report_thread;

static int report_periodic_handle(struct thread *t)
{
	pthread_rwlock_wrlock(&report_lock);
	
	/*执行python脚本完成报表的发送*/
	if (epr.periodic == periodic_none)
	{
		return 0;
	}
		
	char cmd[2048];
	snprintf(cmd, sizeof(cmd), "python /var/reportpy/report.py --periodic-report --periodic \"%d\" --logs \"%s\" --smtpserver \"%s\" --smtpuser \"%s\" --smtppasswd \"%s\" --destmail \"%s\"",
		epr.periodic, epr.logs, epr.smtp_server, epr.smtp_user, epr.smtp_passwd, epr.dest_email);
	cmd_system_novty(cmd);

	/* 再次加入定时器 */
	epr.thread = thread_add_timer(g_report_master, report_periodic_handle, NULL, 60 * 10);
	pthread_rwlock_unlock(&report_lock);
	
	return 0;
}

static int report_timely_handle(struct thread *t)
{
	pthread_rwlock_wrlock(&report_lock);
	/*执行python脚本完成及时告警*/
	
	if (eta.enable == TIMELY_DISABLE)
	{
		return 0;
	}
		
	char cmd[2048];
	snprintf(cmd, sizeof(cmd), "python /var/reportpy/report.py --timely-report --modules \"%s\" --level \"%d\" --frequency %d --smtpserver \"%s\" --smtpuser \"%s\" --smtppasswd \"%s\" --destmail \"%s\"",
		eta.module, eta.level, eta.frequency, eta.smtp_server, eta.smtp_user, eta.smtp_passwd, eta.dest_email);
	
	//SCLogInfo("cmd = %s\n", cmd);
	cmd_system_novty(cmd);

	/* 再次加入定时器 */
	eta.thread = thread_add_timer(g_report_master, report_timely_handle, NULL, eta.interval);
	pthread_rwlock_unlock(&report_lock);
	
	return 0;
}

/*********************************************************************************************************************************
{"periodic":"1","logs":"sys,op","smtpserver":"1.1.1.1","smtpuser":"zhangsan","smtppasswd":"123","destemail":"11@163.com"}
{"enable":"1","modules":"sys,access","level":"1","frequency":"10","smtpserver":"1.1.1.1","smtpuser":"zhangsan","smtppasswd":"123","destemail":"11@163.com"}
*********************************************************************************************************************************/

DEFUN(gap_ctl_report,
	gap_ctl_report_cmd,
	"report (periodic|timely) .JSON",
	"report command\n"
	"periodic email report\n"
	"timely email alarm\n"
	"json parameter, such as:{'xx':'yy',.....}\n")
{
	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	struct json_object *jobj = json_tokener_parse(argv[1]);
	if (!jobj) 
	{
		vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
		SCLogInfo("Call json_tokener_parse() failed.");
		return CMD_ERR_NOTHING_TODO;
	}

	pthread_rwlock_wrlock(&report_lock);
	if (0 == strcmp(argv[0], "periodic")) 
	{
		epr.periodic = jobj_get_int(jobj, "periodic");
		epr.logs = jobj_get_str(jobj, "logs");
		epr.smtp_server = jobj_get_str(jobj, "smtpserver");
		epr.smtp_user = jobj_get_str(jobj, "smtpuser");
		epr.smtp_passwd = jobj_get_str(jobj, "smtppasswd");
		epr.dest_email = jobj_get_str(jobj, "destemail");
		
		if (!(epr.logs) || !(epr.smtp_server) || !(epr.smtp_user) || !(epr.smtp_passwd) || !(epr.dest_email)) 
		{
			vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
			SCLogInfo("Call jobj_get_str() failed:%d,%p,%p,%p,%p,%p.", epr.periodic, epr.logs, epr.smtp_server, epr.smtp_user, epr.smtp_passwd, epr.dest_email);
			pthread_rwlock_unlock(&report_lock);
			return CMD_ERR_NOTHING_TODO;
		}

		if (epr.jobj) 
		{
			json_object_put(epr.jobj);
		}
		if (epr.json) 
		{
			SCFree(epr.json);
		}
		epr.jobj = jobj;
		epr.json = SCStrdup(argv[1]);

		if (epr.thread)
		{
			thread_cancel(epr.thread);
			epr.thread = NULL;
		}
		/* 开启定时任务 */
		if (epr.periodic != periodic_none) 
		{
			epr.interval = 24 * 60 * 60;
			if (epr.periodic == periodic_weekly)
				epr.interval *= 7;
			else if (epr.periodic == periodic_monthly)
				epr.interval *= 30;

			epr.thread = thread_add_timer(g_report_master, report_periodic_handle, NULL, 30);
		}
	}
	else 
	{
		eta.enable = jobj_get_int(jobj, "enable");
		eta.module = jobj_get_str(jobj, "modules");
		eta.level = jobj_get_int(jobj, "level");
		eta.frequency = jobj_get_int(jobj, "frequency");
		eta.smtp_server = jobj_get_str(jobj, "smtpserver");
		eta.smtp_user = jobj_get_str(jobj, "smtpuser");
		eta.smtp_passwd = jobj_get_str(jobj, "smtppasswd");
		eta.dest_email = jobj_get_str(jobj, "destemail");
		
		if (!(eta.module) || !(eta.smtp_server) || !(eta.smtp_user) || !(eta.smtp_passwd) || !(eta.dest_email)) 
		{
			vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
			SCLogInfo("Call jobj_get_str() failed:%d,%p,%d,%d,%p,%p,%p,%p.", eta.enable, eta.module, eta.level, eta.frequency, eta.smtp_server, eta.smtp_user, eta.smtp_passwd, eta.dest_email);
			pthread_rwlock_unlock(&report_lock);
			return CMD_ERR_NOTHING_TODO;
		}

		if (eta.jobj) 
		{
			json_object_put(eta.jobj);
		}
		if (eta.json) 
		{
			SCFree(eta.json);
		}
		eta.jobj = jobj;
		eta.json = SCStrdup(argv[1]);

		if (eta.thread) 
		{
			thread_cancel(eta.thread);
			eta.thread = NULL;
		}
		
		/* 开启定时任务 */
		if (eta.enable == TIMELY_ENABLE) 
		{
			eta.interval = eta.frequency;
			eta.thread = thread_add_timer(g_report_master, report_timely_handle, NULL, eta.interval);
		}
	}
	pthread_rwlock_unlock(&report_lock);

	/* warm sync */
	WARM_SYNC(vty->buf);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_report,
	gap_ctl_report_o_cmd,
	"outer report (periodic|timely) .JSON",
	"outer machine\n"
	"report command\n"
	"periodic email report\n"
	"timely email alarm\n"
	"json parameter, such as:{'xx':'yy',.....}\n");

DEFUN(gap_ctl_show_report,
	gap_ctl_show_report_cmd,
	"show report (periodic|timely)",
	SHOW_STR
	"report config\n"
	"periodic email report\n"
	"timely email alarm\n"
)
{
	SHOW_CMD_RUN();

	pthread_rwlock_rdlock(&report_lock);
	if (0 == strcmp(argv[0], "periodic")) 
	{
		if (epr.json)
		{
			vty_out(vty, "%s%s", epr.json, VTY_NEWLINE);
		}
		else 
		{
			vty_out(vty, "NULL%s", VTY_NEWLINE);
		}
	}
	else
	{
		if (eta.json) 
		{
			vty_out(vty, "%s%s", eta.json, VTY_NEWLINE);
		}
		else 
		{
			vty_out(vty, "NULL%s", VTY_NEWLINE);
		}
	}
	pthread_rwlock_unlock(&report_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_show_report,
	gap_ctl_show_report_o_cmd,
	"show outer report (periodic|timely)",
	SHOW_STR
	"outer machine\n"
	"report config\n"
	"periodic email report\n"
	"timely email alarm\n"
);

static int timer_default_fun(struct thread *t)
{
	//printf("Call timer_default_fun()\n");
	thread_add_timer(g_report_master, timer_default_fun, NULL, 10);
	return 0;
}

static void* report_fun(void *args)
{
	/* Prepare master thread. */
	static struct thread thread;
	while (thread_fetch(g_report_master, &thread)) 
	{
		thread_call(&thread);
	}
	
	return NULL;
}

int report_timer_init(void)
{
	g_report_master = thread_master_create();
	
	thread_add_timer(g_report_master, timer_default_fun, NULL, 0);
	
	int ret_val = pthread_create(&g_report_thread, NULL, report_fun, NULL);
	if (ret_val != 0) 
	{
		SCLogInfo("pthread_create error!");
		return -1;
	}
	return 0;
}

int report_config_write(struct vty *vty)
{
	pthread_rwlock_rdlock(&report_lock);
	if (epr.json) 
	{
		vty_out(vty, "report periodic %s%s", epr.json, VTY_NEWLINE);
	}

	if (eta.json) 
	{
		vty_out(vty, "report timely %s%s", eta.json, VTY_NEWLINE);
	}
	pthread_rwlock_unlock(&report_lock);

	return 0;
}

void report_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_report_cmd);
	install_element(CONFIG_NODE, &gap_ctl_report_o_cmd);
}

void report_show_cmd_init(unsigned int machine)
{
	if (machine == outer_machine || machine == inner_machine) 
	{
		install_element(VIEW_NODE, &gap_ctl_show_report_cmd);
		install_element(ENABLE_NODE, &gap_ctl_show_report_o_cmd);
	}
}

void report_init(void)
{
	if (report_timer_init()) 
	{
		SCLogInfo("Call report_timer_init() failed.");
		return;
	}
	
	pthread_rwlock_init(&report_lock, NULL);
	epr.periodic = 0;
	epr.json = NULL;
	epr.jobj = NULL;
	epr.thread = NULL;

	eta.enable = 0;
	eta.json = NULL;
	eta.jobj = NULL;
	eta.thread = NULL;
}

void report_exit(void)
{
	pthread_rwlock_wrlock(&report_lock);
	if (epr.jobj)
	{
		json_object_put(epr.jobj);
	}
	if (epr.json) 
	{
		SCFree(epr.json);
	}

	if (eta.jobj) 
	{
		json_object_put(eta.jobj);
	}
	if (eta.json) 
	{
		SCFree(eta.json);
	}
	pthread_rwlock_unlock(&report_lock);
}

