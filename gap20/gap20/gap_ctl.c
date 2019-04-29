
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
#include "gap_stgy.h"
#include "main_inouter.h"
#include "gap_cmd_ipmac.h"
#include "gap_cmd_log.h"
#include "gap_cmd_state.h"
#include "gap_cmd_route.h"
#include "gap_ctl_conf.h"
#include "gap_cmd_user.h"
#include "gap_cmd_group.h"
#include "gap_cmd_service.h"
#include "gap_cmd_http.h"
#include "gap_cmd_ftp.h"
#include "gap_cmd_file_sync.h"
#include "gap_cmd_mail.h"
#include "parser_modbus.h"
#include "gap_cmd_opc.h"
#include "gap_cmd_dbsecurity.h"
#include "gap_cmd_report.h"

static char *vty_addr = "127.0.0.1";
extern struct thread_master *master;
static int vty_port = GAP_VTY_PORT;
char *config_default_dir = SYSCONFDIR "gap20_vty.conf.priv";
char *config_file = SYSCONFDIR "gap20_vty.conf";

/*
 *	Lock : for miscellaneous lookups
 */
static pthread_mutex_t misc_lock;
static unsigned int  machine_view = inner_machine;
static unsigned int g_machine = 0;

int translate_ipset(char *ipset, struct ip_range ir[], int *num)
{
	int ir_num = 0;
	*num = 0;
	char *first, *second;
	char *token, *p, *out_ptr = NULL, old;
	char ips[1024], *ip = ips;
	strncpy(ips, ipset, sizeof(ips));
	while ((p = strtok_r(ip, ";,", &out_ptr)) != NULL)
	{
		if (ir_num >= MAX_IPRANGE_SIZE) {
			SCLogInfo("Iprange num overload.");
			return -1;
		}

		ip = NULL;
		first = p;
		old = 0;

		if (NULL != (token = strchr(p, '/'))) {
			old = *token;
			*token = '\0';
			second = token + 1;
			if (inet_pton(AF_INET, first, &ir[ir_num].first_ip) <= 0)
			{
				SCLogInfo("Transform ip failed, ip = %s.", first);
				return -1;
			}
			ir[ir_num].first_ip = ntohl(ir[ir_num].first_ip);
			ir[ir_num].second_ip = atoi(second);
			ir[ir_num].suffix = atoi(second);
			ir[ir_num].type = 3;
			unsigned int mask = (~((1 << (32 - ir[ir_num].second_ip)) - 1));
			ir[ir_num].first_ip = (ir[ir_num].first_ip&mask) + 1;
			ir[ir_num].second_ip = ir[ir_num].first_ip | (~mask);
		}
		else if (NULL != (token = strchr(p, '-'))) {
			old = *token;
			*token = '\0';
			second = token + 1;
			if (inet_pton(AF_INET, first, &ir[ir_num].first_ip) <= 0)
			{
				SCLogInfo("Transform ip failed, ip = %s.", first);
				return -1;
			}
			ir[ir_num].first_ip = ntohl(ir[ir_num].first_ip);

			if (inet_pton(AF_INET, second, &ir[ir_num].second_ip) <= 0)
			{
				SCLogInfo("Transform ip failed, ip = %s.", second);
				return -1;
			}
			ir[ir_num].second_ip = ntohl(ir[ir_num].second_ip);
			ir[ir_num].suffix = 0;
			ir[ir_num].type = 2;
		}
		else {
			if (inet_pton(AF_INET, first, &ir[ir_num].first_ip) <= 0)
			{
				SCLogInfo("Transform ip failed, ip = %s.", first);
				return -1;
			}
			ir[ir_num].first_ip = ntohl(ir[ir_num].first_ip);
			ir[ir_num].second_ip = ir[ir_num].first_ip;
			ir[ir_num].suffix = 0;
			ir[ir_num].type = 1;
		}

		if (old)
			*token = old;

		ir_num++;
	}

	*num = ir_num;
	return 0;
}

static struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if-%s)# ",
  1 /* VTYSH */
};

static struct cmd_node gap_outer_node =
{
	GAP_OUTER_NODE,
	"%s(outer)#",
	1,
	NULL,
	NULL
};
static struct cmd_node gap_inner_node =
{
	GAP_INNER_NODE,
	"%s(inner)#",
	1,
	NULL,
	NULL
};
static struct cmd_node gap_arbiter_node =
{
	GAP_ARBITER_NODE,
	"%s(arbiter)#",
	1,
	NULL,
	NULL
};

int check_privilege(struct acl_data *ad, char proto[], char rule[], int len)
{
	struct gap_group_rule *group = NULL;
	int ret = 0;
	/* 用户权限校验 */
	ret = check_user_privilege(ad, &group, rule, len);
	if (ret || group == NULL)
		return ret;

	/* 保存用户组，给后续扩展功能使用 */
	strncpy(ad->groupname, group->groupname, sizeof(ad->groupname));
	ad->group = group;

	/* 用户组权限校验 */
	ret = check_group_privilege(ad, group, proto, rule, len);

	return ret;
}

unsigned int get_cur_machine(void)
{
	unsigned int machine;
	pthread_mutex_lock(&misc_lock);
	machine = g_machine;
	pthread_mutex_unlock(&misc_lock);

	return machine;
}

void register_pfun(print_session_fun fun)
{
}

static int gap_config_write(struct vty *vty)
{
	return 0;
}

static int gap_config_write_inner(struct vty *vty)
{
	/* configure 视图 */
	service_config_write(vty);

	ipmac_config_write(vty);
	group_config_write(vty);
	user_config_write(vty);
	timemgr_config_write(vty);
	route_config_write(vty);
	log_config_write(vty);
	ftp_config_write(vty);
	report_config_write(vty);
	account_config_write(vty);
	return 0;
}

static int gap_config_write_outer(struct vty *vty)
{
	/* configure 视图 */
	service_config_write(vty);

	ipmac_config_write(vty);
	group_config_write(vty);
	user_config_write(vty);
	timemgr_config_write(vty);
	route_config_write(vty);
	log_config_write(vty);
	ftp_config_write(vty);
	report_config_write(vty);
	account_config_write(vty);
	return 0;
}

static void node_cmd_init(void)
{
	install_node(&interface_node, NULL);
	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &interface_outer_cmd);

	if (RUN_AS_INNER())
		install_node(&gap_inner_node, gap_config_write_inner);
	else
		install_node(&gap_inner_node, gap_config_write);

	if (RUN_AS_INNER())
		install_node(&gap_outer_node, gap_config_write);
	else
		install_node(&gap_outer_node, gap_config_write_outer);

	install_default(GAP_OUTER_NODE);
	install_default(GAP_INNER_NODE);
}

int gap_ctl_init(unsigned int machine)
{
	pthread_mutex_init(&misc_lock, NULL);
	g_machine = machine;
	machine_view = machine;

	/* 初始化命令模块 */
	ipmac_init();
	state_init();
	user_init();
	group_init();
	route_init();
	timemgr_init();
	http_cmd_init();
	ftp_cmd_init();
	dbsync_init();
	sync_cmd_init();
	mail_cmd_init();
	opc_cmd_init();
	dbsecurity_cmd_init();
	report_init();
	account_cmd_init();
	/* 初始化命令视图 */
	node_cmd_init();
	access_list_init();

	/* 挂载命令到视图上 */

	service_show_cmd_init(machine);
	service_conf_cmd_init();

	route_show_cmd_init(machine);
	route_conf_cmd_init();

	ipmac_show_cmd_init(machine);
	ipmac_conf_cmd_init();

	user_show_cmd_init(machine);
	user_conf_cmd_init();

	group_show_cmd_init(machine);
	group_conf_cmd_init();

	log_show_cmd_init(machine);
	log_conf_cmd_init();

	state_show_cmd_init(machine);
	state_conf_cmd_init();

	timemgr_show_cmd_init(machine);
	timemgr_conf_cmd_init();

	ftp_show_cmd_init(machine);
	ftp_conf_cmd_init();

	report_conf_cmd_init();
	report_show_cmd_init(machine);

	sync_conf_cmd_init();

	mail_conf_cmd_init();

	modbus_conf_cmd_init();
	opc_conf_cmd_init();

	account_show_cmd_init(machine);
	account_conf_cmd_init();
	return 0;
}

void gap_ctl_exit(void)
{
	if (!g_machine)
		return;

	ipmac_exit();
	route_exit();
	user_exit();
	group_exit();
	timemgr_exit();
	http_cmd_exit();
	ftp_cmd_exit();
	dbsync_exit();
	dbsecurity_cmd_exit();
	report_exit();
}

int gap_vty_outer_chain_cb(struct vty* vty, int ret)
{
	char *cp;
	struct vty_adapter *adpt;
	if (ret != CMD_SUCCESS)
		return CMD_SUCCESS;

	adpt = ((struct vty_adapter *) vty->usr_data);
	if (!adpt)
		return CMD_SUCCESS;

	cp = vty->buf;
	while (isspace(*cp))
		cp++;

	if (!cp || *cp == '\0')
		return CMD_SUCCESS;

	if (strncmp(cp, "show", 4) == 0)
		return CMD_SUCCESS;

	if (strncmp(cp, "enable", strlen("enable")) == 0
		|| strncmp(cp, "configure", strlen("configure")) == 0
		|| strncmp(cp, "end", strlen("end")) == 0
		|| strncmp(cp, "quit", strlen("quit")) == 0
		|| strncmp(cp, "exit", strlen("exit")) == 0
		|| (strncmp(cp, "write", strlen("write")) == 0
			&& (strstr(cp, "file") || strstr(cp, "memory"))))
		return vty_adapter_run(vty, adpt);

	return CMD_SUCCESS;
}

struct vty_chain gap_vty_o_chain =
{
	.func = gap_vty_outer_chain_cb
};

int gap_vty_init(unsigned int machine)
{
	cmd_init(1);
	vty_init(master);
	memory_init();

	/* init ctl */
	gap_ctl_init(machine);

	/* Make vty server socket.  add new vty tunnel,2017.1.17 */
	if (machine == outer_machine) 
	{
		vty_addr = OUTER_DEFAULT_IP_STR;
		vty_serv_sock("127.0.0.1", vty_port, NULL);
	}
	else
	{
		vty_add_hook(VTY_CREATE_HOOK, vty_adapter_create);
		vty_add_hook(VTY_CLOSE_HOOK, vty_adapter_close);

		vty_chain_register(&gap_vty_o_chain);

		haa_vty_add_hook();
	}

	/* Init cmd conf */
	if (conf_init())
	{
		SCLogInfo("Call conf_init failed.");
		return -1;
	}
	
	/* Init conf ha */
	if (have_ha()) 
	{
		if (gap_ha_init(machine)) 
		{
			SCLogInfo("Call gap_ha_init failed.");
			return -1;
		}
	}
	else 
	{
		/* Get configuration file. */
		vty_read_config(config_file, config_default_dir);
	}

	/* Create VTY's socket */
	vty_serv_sock(vty_addr, vty_port, APP_VTYSH_PATH);
	
	return 0;
}

void gap_vty_exit(void)
{
	gap_ctl_exit();
}