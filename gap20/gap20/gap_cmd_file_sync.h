/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : gap_cmd_file_sync.h
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.3.29
Description    : SYNC VTY
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#ifndef __GAP_CMD_SYNC_H__
#define __GAP_CMD_SYNC_H__
#include "app_common.h"

/* sync show command init */
void sync_show_cmd_init(unsigned int machine);

/* sync config command init */
void sync_conf_cmd_init(void);

/* sync cmd init */
void sync_cmd_init(void);

/* sync cmd exit */
void sync_cmd_exit(void);

#endif

