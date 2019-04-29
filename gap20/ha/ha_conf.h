#ifndef _HA_CONF_H_
#define _HA_CONF_H_

#define HA_CONF_TIMEOUT_VAL (3000)						/* ms */

typedef enum _HaConfMsgType
{
	HA_CONF_MSG_STOP_TIMER,
	HA_CONF_MSG_CLOSE_SOCKET,
	HA_CONF_MSG_CONFIGURATION_CMDS,
	HA_CONF_MSG_RECOVER,
	HA_CONF_MSG_GO_OOS,
	HA_CONF_MSG_REELECTION,
	HA_CONF_MSG_MAX,
}HaConfMsgType;

typedef struct _HaConfMsg
{
	int				nPeerOuter;							//是否为对端外端机
	HaConfMsgType	nMsgType;							//配置消息类型
	int				nLength;							//数据长度
	char			chData[HA_CONF_CMD_LEN];			//配置数据信息
}HaConfMsg;

int HaSendConfigData(char* pMsg, int nLength);
void SaveLocalConfigurationCmds(const char* pCmds, int nLength);
void ApplyLocalConfigurationCmds();

#endif