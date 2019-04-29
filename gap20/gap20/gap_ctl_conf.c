
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
#include "gap_ctl_conf.h"
#include "gap_cmd_route.h"
#include "gap_cmd_http.h"

int conf_init(void)
{
	char cmd[1024];
	int ret;

	/* table for web */
	snprintf(cmd, sizeof(cmd), "sqlite3 "DATABASE_CFG"\""SQLITE3_PARAM"create table "WEB_CONF_TABLE"(id   integer PRIMARY KEY autoincrement, key varchar(256), value varchar(256))\""DEV_NULL);
	ret = cmd_system_novty(cmd);

	return 0;
}

void conf_exit(void)
{
}

