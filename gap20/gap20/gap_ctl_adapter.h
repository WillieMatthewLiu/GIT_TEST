#ifndef _GAP_ARBITER_ADAPTER_H_
#define _GAP_ARBITER_ADAPTER_H_
#include "oscall.h"
#include "gap_ctl.h"
#include "command.h"

/* begin---------------add new CTL tunnel  , 2017.1.17 */

/*查询命令远端执行 */
#define SHOW_CMD_RUN() \
do{\
	if(RUN_AS_INNER() && strstr(self->string, "outer")){\
		if(vty->usr_data){\
		  vty_adapter_run(vty,((struct vty_adapter *) vty->usr_data));\
		  return CMD_SUCCESS;\
		}else{return CMD_ERR_NOTHING_TODO;}\
	}\
}while(0)

/* 配置命令远端执行 */
#define CONF_CMD_RUN()\
do{\
	if(RUN_AS_INNER() && (strncmp(self->string, "outer", strlen("outer")) == 0)){\
		if(vty->usr_data){\
			if(-1==vty_adapter_run(vty,((struct vty_adapter *) vty->usr_data))){\
				return CMD_ERR_NOTHING_TODO;\
			}\
			return CMD_SUCCESS;\
		}else{return CMD_ERR_NOTHING_TODO;}\
	}\
}while(0)

#define CONFIG_SYNC_CMD() \
do{\
    if(RUN_AS_INNER() && vty->usr_data)\
    {\
        if(vty_adapter_run(vty, vty->usr_data) < 0){\
            return CMD_ERR_NOTHING_TODO;\
        }\
    }\
}while(0)

/* end---------------add new CTL tunnel  , 2017.1.17 */

int vty_adapter_create(struct vty *vty);
int vty_adapter_close(struct vty *vty);

#endif

