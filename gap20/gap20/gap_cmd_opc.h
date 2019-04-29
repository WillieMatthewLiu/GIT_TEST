/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : gap_cmd_opc.h
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.6.14
Description    : opc vty
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#ifndef __GAP_CMD_OPC_H__
#define __GAP_CMD_OPC_H__
#include "app_common.h"

/* config */
#define OPC_CONFIG_GROUP_NAME       "groupName"
#define OPC_CONFIG_MODE             "mode"
#define OPC_CONFIG_VALID            "valid"

/* opc config command init */
void opc_conf_cmd_init(void);

/* opc cmd init */
void opc_cmd_init(void);

/* opc cmd exit */
void opc_cmd_exit(void);

#endif
