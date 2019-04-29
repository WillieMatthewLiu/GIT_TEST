
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
#include "gap_cmd_state.h"
#include "gapconfig.h"

#define TSAR_CRON      "/etc/tsar_cron.sh"
#define GAP_CONF "gap20_vty.conf"
#define HA_CONF "ha.conf"
#define ZEBRA_CONF "zebra.conf"
struct sys_rate
{
	char cpu[12];
	char mem[12];
	char disk[12];
};

struct sys_throughput
{
	char if_total_up_bandwidth[32];
	char if_total_down_bandwidth[32];
};

const char* interface_array[INTERFACE_NUM] = { "P0", "P1", "P2","P3", "P4", "P5", "HA", "MGMT" };
extern unsigned int user_count;
extern unsigned int ipmac_count;
extern unsigned int rt_count;

DEFUN(gap_set_time,
	gap_set_time_cmd,
	"set time WORD",
	"Set time to system.\n"
	"time\n"
	"eg: 2016/06/29-15:20:30\n"
)
{
	char cmd[1024];
	char *p = NULL;

	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	if (NULL != (p = strchr(argv[0], '-')))
		*p = ' ';

	snprintf(cmd, sizeof(cmd), "date -s \"%s\" 2>&1  && hwclock -w  ", argv[0]);

	int ret = cmd_system_novty(cmd);
	if (ret) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	/* warm sync */
	WARM_SYNC(vty->buf);
	return CMD_SUCCESS;
}

ALIAS(gap_set_time,
	gap_set_time_o_cmd,
	"outer set time WORD",
	"outer machine\n"
	"Set time to system.\n"
	"time\n"
	"eg: 2016/06/29-15:20:30\n"
);

DEFUN(gap_show_time,
	gap_show_time_cmd,
	"show time",
	SHOW_STR
	"current time.\n"
)
{
	SHOW_CMD_RUN();

	time_t t = time(0);
	char buf[64];
	strftime(buf, sizeof(buf), "%Y/%m/%d-%H:%M:%S", localtime(&t));
	vty_out(vty, "Local time is: %s%s", buf, VTY_NEWLINE);

	return CMD_SUCCESS;
}

ALIAS(gap_show_time,
	gap_show_time_o_cmd,
	"show outer time",
	SHOW_STR
	"outer machine\n"
	"current time.\n");

DEFUN(gap_set_ntp,
	gap_set_ntp_cmd,
	"set ntp A.B.C.D",
	"Set ntp server\n"
	"NTP\n"
	"ip address,eg:24.56.178.140\n"
)
{
	char cmd[256];
	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	snprintf(cmd, sizeof(cmd), "ntpdate %s;echo \"1 1 * * * root ntpdate %s\" >/etc/cron.d/time_ntp", argv[0], argv[0]);
	int ret = cmd_system_novty(cmd);
	if (ret) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	/* warm sync */
	WARM_SYNC(vty->buf);
	return CMD_SUCCESS;
}

ALIAS(gap_set_ntp,
	gap_set_ntp_o_cmd,
	"outer set ntp A.B.C.D",
	"outer machine\n"
	"Set ntp server\n"
	"NTP\n"
	"ip address,eg:24.56.178.140\n"
);

DEFUN(gap_show_ntp,
	gap_show_ntp_cmd,
	"show ntp",
	SHOW_STR
	"NTP server\n"
)
{
	SHOW_CMD_RUN();

	char cmd[128];
	char buf[1024] = { 0 };
	FILE *fp_read = NULL;
	snprintf(cmd, sizeof(cmd), "cat /etc/cron.d/time_ntp "DEV_NULL);
	fp_read = popen(cmd, "r");
	if (fp_read == NULL) {
		SCLogInfo("Call popen failed, cmd=%s", cmd);
		return CMD_SUCCESS;
	}
	while (fgets(buf, sizeof(buf), fp_read) != NULL) {
		char *p = strstr(buf, "ntpdate ");
		if (p) {
			vty_out(vty, "ntp server is %s%s", p + strlen("ntpdate "), VTY_NEWLINE);
			break;
		}
		memset(buf, 0, sizeof(buf));
	}
	pclose(fp_read);
	return CMD_SUCCESS;
}

ALIAS(gap_show_ntp,
	gap_show_ntp_o_cmd,
	"show outer ntp",
	SHOW_STR
	"outer machine\n"
	"NTP: 24.56.178.140\n");

static void get_run_time(char *value, int len)
{
	FILE *fp_read = NULL;
	char cmd[128];
	char buf[128], *p;
	int second;

	memset(value, 0, len);
	sprintf(cmd, "cat /proc/uptime");
	fp_read = popen(cmd, "r");
	if (fp_read == NULL) {
		return;
	}

	if (fgets(buf, sizeof(buf), fp_read) != NULL) {
		if ((p = strchr(buf, ' ')) != NULL) {
			*p = '\0';
			second = atoi(buf);
			sprintf(buf, "%dDay%dHour%dMin%dSec", second / 86400, (second % 86400) / 3600, (second % 3600) / 60, second % 60);
			strncpy(value, buf, len);
		}
	}
	pclose(fp_read);
}

static void get_ha_state(char *value, int len)
{
	memset(value, 0, len);
	if (get_hastate() == ha_master)
		strncpy(value, "master", len);
	else if (get_hastate() == ha_slave)
		strncpy(value, "slave", len);
	else
		strncpy(value, "oos", len);
}

static void get_svc_state(char *value, int len)
{
	memset(value, 0, len);
	strncpy(value, "normal", len);
}

static void get_rate(struct sys_rate *sr)
{
	FILE *fp_read = NULL;
	char cmd[64];
	char buf[1024], *start, *end;

	cmd_system_novty("/usr/bin/tsar --cron > /dev/null 2>&1");
	memset(sr, 0, sizeof(*sr));
	sprintf(cmd, "tsar -C");
	fp_read = popen(cmd, "r");
	if (fp_read == NULL) {
		return;
	}

	if (fgets(buf, sizeof(buf), fp_read) != NULL) {
		int slen = strlen("cpu:util=");
		if ((start = strstr(buf, "cpu:util=")) != NULL) {
			end = strchr(start, ' ');
			strncpy(sr->cpu, start + slen, end - start - slen);
		}

		slen = strlen("mem:util=");
		if ((start = strstr(buf, "mem:util=")) != NULL) {
			end = strchr(start, ' ');
			strncpy(sr->mem, start + slen, end - start - slen);
		}

		start = strstr(buf, "partition");
		if (start) {
			double disk = 0.0;
			int n = 0;
			end = start;
			slen = strlen(":util=");
			while ((start = strstr(end, ":util=")) != NULL) {
				end = start + slen;
				disk += atof(start + slen);
				n++;
			}
			sprintf(sr->disk, "%.1f", disk / n);
		}
	}
	pclose(fp_read);
}

static void get_if_throughput(struct sys_throughput *st)
{
	FILE *fp_read = NULL;
	char cmd[64];
	char buf[256], *start, *end;

	memset(st, 0, sizeof(*st));
	sprintf(cmd, "tsar -C --traffic -s bytin,bytout");
	fp_read = popen(cmd, "r");
	if (fp_read == NULL) {
		return;
	}

	if (fgets(buf, sizeof(buf), fp_read) != NULL) {
		int slen;
		char keyword[64];
		sprintf(keyword, "traffic:bytin=");
		slen = strlen(keyword);
		if ((start = strstr(buf, keyword)) != NULL) {
			end = strchr(start, ' ');
			strncpy(st->if_total_down_bandwidth, start + slen, end - start - slen);
		}

		sprintf(keyword, "traffic:bytout=");
		slen = strlen(keyword);
		if ((start = strstr(buf, keyword)) != NULL) {
			end = strchr(start, ' ');
			strncpy(st->if_total_up_bandwidth, start + slen, end - start - slen);
		}
	}
	pclose(fp_read);
}

static int get_link_state(char *name)
{
	int fd, ret;
	struct interface *ifp = if_lookup_by_name(name);
	if (!ifp)
		return 0;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		return 0;
	}

	struct ifreq ifr;
	struct ethtool_value edata;
	edata.cmd = ETHTOOL_GLINK;
	edata.data = 0;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifp->name);
	ifr.ifr_data = (char *)&edata;

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret < 0)
	{
		close(fd);
		return 0;
	}

	close(fd);
	return (edata.data ? 1 : 0);
}

static void get_if_state(int if_state[])
{
	int i;
	for (i = 0; i < INTERFACE_NUM; i++) {
		if_state[i] = get_link_state(interface_array[i]);
	}
}

static int get_sn(char *value, int len)
{
	FILE *fp_read = NULL;
	char cmd[128];
	char buf[256], *token;

	snprintf(cmd, sizeof(cmd), "rongan_eeprom read serialnum");
	fp_read = popen(cmd, "r");
	if (fp_read == NULL) {
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	if (fgets(buf, sizeof(buf), fp_read) != NULL) {
		if ((token = strchr(buf, '\n')))
			*token = '\0';
		if ((token = strchr(buf, '\r')))
			*token = '\0';
		strncpy(value, buf, len);
	}
	pclose(fp_read);
	return 0;
}

DEFUN(gap_show_status,
	gap_show_status_cmd,
	"show status",
	SHOW_STR
	"machine status\n"
)
{
	struct sys_rate sr;
	char sys_time[64];
	char run_time[128];
	char ha_state[12];
	char svc_state[12];
	long total_rule = 0;
	SHOW_CMD_RUN();

	int if_state[INTERFACE_NUM];
	struct sys_throughput st;
	int user_rule_count = 0;
	int ipmac_rule_count = 0;

	/* public info */
	get_rate(&sr);
	get_sys_time(sys_time, sizeof(sys_time), "%Y-%m-%d %H:%M:%S");
	get_run_time(run_time, sizeof(run_time));
	get_ha_state(ha_state, sizeof(ha_state));
	get_svc_state(svc_state, sizeof(svc_state));

	/* private info */
	int i = 0;
	get_if_state(if_state);
	get_if_throughput(&st);

	total_rule = rt_count;
	vty_out(vty, "Time=%s%s"
		"Runtime=%s%s"
		"Ha-state=%s%s"
		"Service-state=%s%s"
		"Cpu=%s%s"
		"Mem=%s%s"
		"Disk=%s%s"
		"Total-rules=%ld%s", sys_time, VTY_NEWLINE, run_time, VTY_NEWLINE, ha_state, VTY_NEWLINE, svc_state, VTY_NEWLINE, sr.cpu, VTY_NEWLINE, sr.mem, VTY_NEWLINE, sr.disk, VTY_NEWLINE,
		total_rule, VTY_NEWLINE);
	vty_out(vty, "traffic-up-bandwidth=%s%straffic-down-bandwidth=%s%s",
		st.if_total_up_bandwidth, VTY_NEWLINE, st.if_total_down_bandwidth, VTY_NEWLINE);
	for (i = 0; i < INTERFACE_NUM; i++) {
		vty_out(vty, "%s-state=%d%s", interface_array[i], if_state[i], VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

ALIAS(gap_show_status,
	gap_show_status_o_cmd,
	"show outer status",
	SHOW_STR
	"outer machine\n"
	"machine status\n");

DEFUN(gap_show_traffic,
	gap_show_traffic_cmd,
	"show traffic",
	SHOW_STR
	"bytin and bytout of traffic\n"
)
{
	FILE *fp_read = NULL;
	char cmd[128];
	char buf[256], *token;
	SHOW_CMD_RUN();

#define POINT_NUM 10
	time_t end = time(NULL);
	time_t begin = end - (POINT_NUM * 60 + 30);
	time_t t;

	sprintf(cmd, "tsar -i 1 -D --traffic -s bytin,bytout|grep \"Record\"|tail -n 60");
	fp_read = popen(cmd, "r");
	if (fp_read == NULL) {
		return CMD_SUCCESS;
	}

	memset(buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), fp_read) != NULL) {
		if ((token = strchr(buf, '\n')))
			*token = '\0';
		if ((token = strchr(buf, '\r')))
			*token = '\0';

		if ((token = strchr(buf, ':'))) {
			t = atol(token + 1);
			if (t >= begin && t <= end) {
				vty_out(vty, "%s%s", token + 1, VTY_NEWLINE);
			}
		}
		memset(buf, 0, sizeof(buf));
	}
	pclose(fp_read);

	return CMD_SUCCESS;
}

ALIAS(gap_show_traffic,
	gap_show_traffic_o_cmd,
	"show outer traffic",
	SHOW_STR
	"outer machine\n"
	"bytin and bytout of traffic\n");

DEFUN(gap_system,
	gap_system_cmd,
	"system .LINE",
	"Execute Linux system command\n"
	"command\n"
)
{
	char *cmd = NULL;
	char buf[2048];
	memset(buf, 0, sizeof(buf));

	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	cmd = strstr(vty->buf, "system");
	if (cmd) {
		cmd += sizeof("system");
	}
	else {
		vty_result(ERR_CODE_PARAMERROR, ERR_CODE_PARAMERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	FILE *fp_read = popen(cmd, "r");
	if (fp_read == NULL) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	while (fgets(buf, sizeof(buf), fp_read) != NULL) {
		vty_out(vty, "%s%s", buf, VTY_NEWLINE);
		memset(buf, 0, sizeof(buf));
	}

	pclose(fp_read);
	return CMD_SUCCESS;
}

ALIAS(gap_system,
	gap_system_o_cmd,
	"outer system .LINE",
	"outer machine\n"
	"Execute Linux system command\n"
	"command\n"
);

DEFUN(gap_ctl_pull_outer_conf,
	gap_ctl_pull_outer_conf_cmd,
	"outer pull configution (gap|ha|zebra|all) FILENAME {PATH}",
	"outer machine\n"
	"pull configution from outer machine\n"
	"configution\n"
	"gap Background program\n"
	"ha Background program\n"
	"zebra Background program\n"
	"All options above\n"
	"Generated file name, such as: outer_config.tar.gz\n"
	"Specify source file directory, such as: /etc/\n"
)
{
	char *path = SYSCONFDIR;
	char *gap_conf = "";
	char *ha_conf = "";
	char *zebra_conf = "";
	char cmd[1024];
	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	if (argv[2] != NULL) {
		path = argv[1];
	}

	if (0 == strcmp(argv[0], "gap")) {
		gap_conf = GAP_CONF;
	}
	else if (0 == strcmp(argv[0], "ha")) {
		ha_conf = HA_CONF;
	}
	else if (0 == strcmp(argv[0], "zebra")) {
		zebra_conf = ZEBRA_CONF;
	}
	else {
		gap_conf = GAP_CONF;
		ha_conf = HA_CONF;
		zebra_conf = ZEBRA_CONF;
	}
	snprintf(cmd, sizeof(cmd), "cd %s;tar zcf %s %s %s %s 2>/dev/null", path, argv[1], gap_conf, ha_conf, zebra_conf);
	int ret = cmd_system_novty(cmd);
	if (0 != ret) {
		SCLogInfo("Rum cmd failed, cmd=%s", cmd);
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	snprintf(cmd, sizeof(cmd), "cd %s;tftp -p -l %s 192.168.0.2", path, argv[1]);
	ret = cmd_system_novty(cmd);
	snprintf(cmd, sizeof(cmd), "cd %s;rm -rf %s", path, argv[1]);
	cmd_system_novty(cmd);
	if (0 != ret) {
		SCLogInfo("Rum cmd failed, cmd=%s", cmd);
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}


DEFUN(gap_ctl_push_outer_conf,
	gap_ctl_push_outer_conf_cmd,
	"outer push configution WORD {PATH}",
	"outer machine\n"
	"push configution to outer machine\n"
	"configution\n"
	"configution's name, such as:outer_config.tar.gz\n"
	"Specify Destination file directory, such as: /etc/\n"
)
{
	char *path = SYSCONFDIR;
	char cmd[1024];
	/* ≈‰÷√√¸¡Ó «∑Ò‘∂∂À÷¥–– */
	CONF_CMD_RUN();

	if (argv[1] != NULL) {
		path = argv[1];
	}

	snprintf(cmd, sizeof(cmd), "cd %s;tftp -g -r %s 192.168.0.2", path, argv[0]);
	int ret = cmd_system_novty(cmd);
	snprintf(cmd, sizeof(cmd), "cd %s;tar zxvf %s; rm -rf %s;", path, argv[0], argv[0]);
	cmd_system_novty(cmd);
	if (0 != ret) {
		SCLogInfo("Rum cmd failed, cmd=%s", cmd);
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

static int tsar_cron_init(void)
{
	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "#!/bin/sh\n"
		"rm -rf /var/log/tsar.data.*\n"
		"tsar -c;tsar -c;tsar -c;tsar -c;\n"
		"mv /var/log/tsar.data /var/log/tsar.data.1\n"
		"touch /var/log/tsar.data\n"
		"tsar -c;tsar -c;tsar -c;\n");
	FILE *fp = fopen(TSAR_CRON, "w");
	fwrite(cmd, strlen(cmd), 1, fp);
	fclose(fp);

	snprintf(cmd, sizeof(cmd), "0 */1 * * * root /bin/sh %s\n", TSAR_CRON);
	fp = fopen("/etc/cron.d/tsar_rotate", "w");
	fwrite(cmd, strlen(cmd), 1, fp);
	fclose(fp);

	return 0;
}

void state_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_set_ntp_o_cmd);
	install_element(CONFIG_NODE, &gap_set_time_o_cmd);
	install_element(CONFIG_NODE, &gap_system_o_cmd);

	install_element(CONFIG_NODE, &gap_set_ntp_cmd);
	install_element(CONFIG_NODE, &gap_set_time_cmd);
	install_element(CONFIG_NODE, &gap_system_cmd);
	install_element(CONFIG_NODE, &gap_ctl_pull_outer_conf_cmd);
	install_element(CONFIG_NODE, &gap_ctl_push_outer_conf_cmd);
}

void state_show_cmd_init(unsigned int machine)
{
	if (machine == inner_machine || machine == outer_machine) {
		install_element(VIEW_NODE, &gap_show_ntp_cmd);
		install_element(VIEW_NODE, &gap_show_traffic_cmd);
		install_element(VIEW_NODE, &gap_show_status_o_cmd);
		install_element(VIEW_NODE, &gap_show_ntp_o_cmd);
		install_element(VIEW_NODE, &gap_show_time_o_cmd);
		install_element(VIEW_NODE, &gap_show_traffic_o_cmd);

		install_element(ENABLE_NODE, &gap_show_ntp_cmd);
		install_element(ENABLE_NODE, &gap_show_traffic_cmd);
		install_element(ENABLE_NODE, &gap_show_status_o_cmd);
		install_element(ENABLE_NODE, &gap_show_ntp_o_cmd);
		install_element(ENABLE_NODE, &gap_show_time_o_cmd);
		install_element(ENABLE_NODE, &gap_show_traffic_o_cmd);
	}

	install_element(VIEW_NODE, &gap_show_status_cmd);
	install_element(VIEW_NODE, &gap_show_time_cmd);

	install_element(ENABLE_NODE, &gap_show_status_cmd);
	install_element(ENABLE_NODE, &gap_show_time_cmd);
}

void state_init(void)
{
	tsar_cron_init();
}

void state_exit(void)
{
}

