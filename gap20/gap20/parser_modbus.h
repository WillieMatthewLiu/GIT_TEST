#pragma once

typedef int					BOOL;
typedef unsigned char		BYTE;

static char* g_pModbusDefaultJsonStr = "{\"rule_work\":0,\"readonly\":0,\"black_cmd\":[]}";

/* Configure struct */
typedef struct _MODBUS_CONFIG
{
	BOOL bRuleWork;				//�����Ƿ���Ч
	BOOL bReadOnly;				//ֻ�����ȡ
	BYTE chCommnad[256];		//�����Ƿ�����ִ�У�0������ 1��������
	char chModbusJsonStr[1024];	//Json��ʽ�Ĺ��������ַ���
} MODBUS_CONFIG;

MODBUS_CONFIG g_rModbusConfig;

char* modbus_getConfig(void);
void  modbus_conf_cmd_init(void);