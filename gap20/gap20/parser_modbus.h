#pragma once

typedef int					BOOL;
typedef unsigned char		BYTE;

static char* g_pModbusDefaultJsonStr = "{\"rule_work\":0,\"readonly\":0,\"black_cmd\":[]}";

/* Configure struct */
typedef struct _MODBUS_CONFIG
{
	BOOL bRuleWork;				//规则是否生效
	BOOL bReadOnly;				//只允许读取
	BYTE chCommnad[256];		//命令是否允许执行，0：允许 1：不允许
	char chModbusJsonStr[1024];	//Json格式的规则设置字符串
} MODBUS_CONFIG;

MODBUS_CONFIG g_rModbusConfig;

char* modbus_getConfig(void);
void  modbus_conf_cmd_init(void);