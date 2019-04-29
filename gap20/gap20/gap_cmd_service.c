
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
#include "gap_cmd_route.h"
#include "gapconfig.h"
#include "main_inouter.h"

DEFUN(gap_ctl_service_ctrl,
	gap_ctl_service_ctrl_cmd,
	"service (enable|disable)",
	"service command\n"
	"service enable\n"
	"service disable\n"
)
{
	if (RUN_AS_INNER() && vty->usr_data)
		vty_adapter_run(vty, ((struct vty_adapter*)vty->usr_data));

	int isenable = (strcmp(argv[0], "enable") == 0);

	g_gapcfg->service_enabled = isenable;
	vty_onservice_onoff(isenable);

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_service_status,
	gap_ctl_service_status_cmd,
	"show service status",
	SHOW_STR
	"service command\n"
	"status command\n"
)
{
	vty_out(vty, "%s%s", g_gapcfg->service_enabled ? "enabled" : "disabled", VTY_NEWLINE);
	return CMD_SUCCESS;
}

int service_config_write(struct vty *vty)
{
	vty_out(vty, "service %s%s", g_gapcfg->service_enabled ? "enable" : "disable", VTY_NEWLINE);
	return 0;
}

void service_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_service_ctrl_cmd);
}

void service_show_cmd_init(unsigned int machine)
{
	install_element(VIEW_NODE, &gap_ctl_service_status_cmd);
	install_element(ENABLE_NODE, &gap_ctl_service_status_cmd);
}

void service_init(void)
{
}

void service_exit(void)
{
}

