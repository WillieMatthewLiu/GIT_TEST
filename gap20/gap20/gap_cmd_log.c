
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
#include "main_inouter.h"
#include "gap_cmd_log.h"
#include "db_mysql.h"

static int g_logging_switch = DEFAULT_SWITCH; /* 记录日志，默认开启 */
static int g_log_volume = DEFAULT_MAX_SIZE;/*默认最大容量*/
static int g_log_alarm = DEFAULT_WARN_SIZE;/*默认告警容量*/

extern int session_vtyquery(struct vty *vty, int offset, int count, int id);

DEFUN(gap_enable_logging_switch,
	gap_enable_logging_switch_cmd,
	"logging (enable|disable) {volume <1-10240> | alarm <1-10240>}",
	"logging command\n"
	"logging enable\n"
	"logging disable\n"
	"the volume size of log\n"
	"1M-10240M"
	"the alarm size of log\n"
	"1M-10240M"
)
{
	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	if (0 == strcmp("enable", argv[0])) {
		g_logging_switch = 1;
		cmd_system_novty_arg("rm %s "DEV_NULL, AUDIT_SWITCH_FILE);
	}
	else {
		g_logging_switch = 0;
		cmd_system_novty_arg("echo \"0\" > %s", AUDIT_SWITCH_FILE);
	}

	if (argv[1] != NULL) {
		g_log_volume = atoi(argv[1]);
	}
	if (argv[2] != NULL) {
		g_log_alarm = atoi(argv[2]);
	}
	cmd_system_novty_arg("echo \"%d|%d\" > %s", g_log_volume, g_log_alarm, AUDIT_VOLUME_FILE);

	/* warm sync */
	WARM_SYNC(vty->buf);
	return CMD_SUCCESS;
}

ALIAS(gap_enable_logging_switch,
	gap_enable_logging_switch_o_cmd,
	"outer logging (enable|disable) {volume <1-10240> | alarm <1-10240>}",
	"outer machine\n"
	"logging command\n"
	"logging enable\n"
	"logging disable\n"
	"the volume size of log\n"
	"1M-10240M"
	"the alarm size of log\n"
	"1M-10240M"
);

DEFUN(gap_show_logging_switch,
	gap_show_logging_switch_cmd,
	"show loggingswitch",
	SHOW_STR
	"show logging switch\n"
)
{
	SHOW_CMD_RUN();
	char buf[512];
	print_volume(buf, sizeof(buf), NULL);
	vty_out(vty, "{\"open\":\"%d\",%s}%s", g_logging_switch, buf, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(gap_show_logging_switch,
	gap_show_logging_switch_o_cmd,
	"show outer loggingswitch",
	SHOW_STR
	"outer machine\n"
	"show logging switch\n");

DEFUN(gap_show_mysql_log,
	gap_show_mysql_log_cmd,
	"show (inner|outer) (operationlogs|syslogs|eventauditlogs|accessauditlogs|sessionlogs) {limit <0-2147483647> <1-2147483647>}",
	SHOW_STR
	"inner machine\n"
	"outer machine\n"
	"op log\n"
	"sys log\n"
	"secaudit log\n"
	"accessaudit log\n"
	"session log\n"
	"View the number of records\n"
	"offset\n"
	"limit\n"
)
{
	int offset = 0, count = 100;

	char *table = argv[1];

	if (argv[2] != NULL) {
		offset = atoi(argv[2]);
	}
	if (argv[3] != NULL) {
		count = atoi(argv[3]);
	}

	char *ret = select_log(vty, argv[0], table, offset, count);
	return CMD_SUCCESS;
}

DEFUN(gap_show_session_active_log,
	gap_show_session_active_log_cmd,
	"show session active {limit <0-2147483647> <1-2147483647> | id <1-2147483647>}",
	SHOW_STR
	"show session log\n"
	"Active session\n"
	"View the number of records\n"
	"offset\n"
	"limit\n"
	"id\n"
	"index of record\n"
)
{

	SHOW_CMD_RUN();
	int offset = 0, count = 100, id = 0;
	if (argv[0] != NULL) {
		offset = atoi(argv[0]);
	}
	if (argv[1] != NULL) {
		count = atoi(argv[1]);
	}
	if (argv[2] != NULL) {
		id = atoi(argv[2]);
	}
	session_vtyquery(vty, offset, count, id);
	return CMD_SUCCESS;
}

ALIAS(gap_show_session_active_log,
	gap_show_session_active_log_o_cmd,
	"show outer session active {limit <0-2147483647> <1-2147483647>| id <1-2147483647>}",
	SHOW_STR
	"outer machine\n"
	"show session log\n"
	"Active session\n"
	"id\n"
	"index of record\n");


int get_loggingswitch(void)
{
	return g_logging_switch;
}

void set_loggingswitch(int v)
{
	g_logging_switch = v;
}

int log_config_write(struct vty *vty)
{
	char *value = "enable";
	if (g_logging_switch == 0)
		value = "disable";
	vty_out(vty, "logging %s volume %d alarm %d%s", value, g_log_volume, g_log_alarm, VTY_NEWLINE);
	return 0;
}

void log_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_enable_logging_switch_cmd);
	install_element(CONFIG_NODE, &gap_enable_logging_switch_o_cmd);
}

void log_show_cmd_init(unsigned int machine)
{
	if (machine == inner_machine) {
		install_element(VIEW_NODE, &gap_show_mysql_log_cmd);
		install_element(ENABLE_NODE, &gap_show_mysql_log_cmd);
	}

	if (machine == inner_machine || machine == outer_machine) {

		install_element(VIEW_NODE, &gap_show_logging_switch_cmd);
		install_element(VIEW_NODE, &gap_show_session_active_log_cmd);
		install_element(VIEW_NODE, &gap_show_session_active_log_o_cmd);
		install_element(VIEW_NODE, &gap_show_logging_switch_o_cmd);

		install_element(ENABLE_NODE, &gap_show_logging_switch_cmd);
		install_element(ENABLE_NODE, &gap_show_session_active_log_cmd);
		install_element(ENABLE_NODE, &gap_show_session_active_log_o_cmd);
		install_element(ENABLE_NODE, &gap_show_logging_switch_o_cmd);
	}
}

void cmd_log_init(void)
{
}

void cmd_log_exit(void)
{
}

