#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "app_common.h"
#include "thread.h"
#include "command.h"
#include "util-lock.h"

#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_election.h"
#include "ha_agent.h"
#include "ha_appmgr.h"
#include "ha_statemgr.h"
#include "ha_heartbeat.h"

static HaSysConfig g_rHaSysConfig = 
{
	.chIntface = "eth0",
	.dwLocalMask = HA_DEFAULT_MASK,
	.nLocalPort = HA_DEFAULT_PORT,
	.nPriority = 0,
	.nInitState = HA_STATE_STB,
	.nAutoFailBack = DISABLE,
	.nAuthMode = HA_AUTH_NONE,
	.nIntervalTime = 1000,
	.nWaitTime = 3000,
	.rGarpRefreshTimer.tv_sec = 300,
	.nGarpRepeat = 3,
	.nGarpRefreshRepeat = 3
};

char* HaGetInterfaceName()
{
	return g_rHaSysConfig.chIntface;
}

uint8_t HaGetLocalState()
{
	uint8_t nInitState = g_rHaSysConfig.nInitState;
	return nInitState;
}

uint8_t HaGetLocalRunningState()
{
	mutex_lock(&g_pHaBaseMgr->state_lock);
	uint8_t nHaState = g_pHaBaseMgr->nHaState;
	mutex_unlock(&g_pHaBaseMgr->state_lock);
	
	return nHaState;
}

uint8_t HaGetLocalPriority()
{
	return g_rHaSysConfig.nPriority;
}

uint32_t HaGetLocalIP()
{
	return g_rHaSysConfig.rLocalIPAddr.s_addr;
}

uint32_t HaGetLocalMask()
{
	return g_rHaSysConfig.dwLocalMask;
}

uint16_t HaGetLocalPort()
{
	return g_rHaSysConfig.nLocalPort;
}

int HaGetAuthMode()
{
	return g_rHaSysConfig.nAuthMode;
}

uint8_t HaGetAutoFailback()
{
	return g_rHaSysConfig.nAutoFailBack;
}

uint32_t HaGetHeartbeatIntervalTime()
{
	return g_rHaSysConfig.nIntervalTime;
}

uint32_t HaGetHeartbeatMaxwaitTime()
{
	return g_rHaSysConfig.nWaitTime;
}

int HaSetIPPort(const char* pIP, const char* pMask, uint16_t nPort)
{
	inet_aton(pIP, &g_rHaSysConfig.rLocalIPAddr);
	g_rHaSysConfig.nLocalPort = nPort;
	g_rHaSysConfig.dwLocalMask = inet_addr(pMask);

	cmd_system_arg_real(NULL, "ifconfig %s %s netmask %s up", g_rHaSysConfig.chIntface, pIP, pMask);

	return 0;
}

void HaSetPriority(uint32_t nPriority)
{
	g_rHaSysConfig.nPriority = nPriority;
}

void HaSetInitState(HaState nHaState)
{
	g_rHaSysConfig.nInitState = nHaState;
}

void HaAutoFailbackEnable()
{
	g_rHaSysConfig.nAutoFailBack = ENABLE;
}

void HaAutoFailbackDisable()
{
	g_rHaSysConfig.nAutoFailBack = DISABLE;
}

void HaSetHeartbeatTime(uint32_t nIntervalTime, uint32_t nWaitTime)
{
	g_rHaSysConfig.nIntervalTime = nIntervalTime;
	g_rHaSysConfig.nWaitTime = nWaitTime;
}

int HaSysConfigInit()
{
	int nSockFd = socket(AF_INET, SOCK_STREAM, 0);
	if (nSockFd < 0)
	{
		perror("create socket fail\n");
		return -1;
	}
	
	if (!strlen(g_rHaSysConfig.chIntface)) 
	{
		strcpy(g_rHaSysConfig.chIntface, "eth0");
	}
	
	struct ifreq rIfreq;
	strncpy(rIfreq.ifr_name, g_rHaSysConfig.chIntface, sizeof(rIfreq.ifr_name) - 1);
	
	if ((ioctl(nSockFd, SIOCGIFHWADDR, &rIfreq)) < 0)
	{
		printf("get %s mac ioctl error %s\n", g_rHaSysConfig.chIntface, strerror(errno));
		return -1;
	}
	
	uint32_t dwIP = 0;
	uint8_t  chMacAddr[6];
	
	memcpy(chMacAddr, rIfreq.ifr_hwaddr.sa_data, 6);

	if ((ioctl(nSockFd, SIOCGIFADDR, &rIfreq)) < 0)
	{
		printf("get ip ioctl error %s\n", strerror(errno));
	}
	else
	{
		dwIP = ((struct sockaddr_in *)&(rIfreq.ifr_addr))->sin_addr.s_addr;
	}
		
	if (dwIP == 0)
	{
		char chIPAddr[30] = { 0 };
		struct in_addr rMaskAddr;
		
		if (g_nBoardType == BOARDTYPE_IN)
		{
			snprintf(chIPAddr, 30, "192.168.200.%d", chMacAddr[4] ^ chMacAddr[5]);
		}
		else
		{
			snprintf(chIPAddr, 30, "192.168.201.%d", chMacAddr[4] ^ chMacAddr[5]);
		}

		rMaskAddr.s_addr = g_rHaSysConfig.dwLocalMask;
		HaSetIPPort(chIPAddr, inet_ntoa(rMaskAddr), g_rHaSysConfig.nLocalPort);
	}
	else
	{
		g_rHaSysConfig.rLocalIPAddr = ((struct sockaddr_in*)&(rIfreq.ifr_addr))->sin_addr;
	}

	if (!g_rHaSysConfig.nPriority)
	{
		g_rHaSysConfig.nPriority = chMacAddr[4] ^ chMacAddr[5];
	}
		
	return 0;
}

HaSysConfig* HaGetConfig()
{
	return &g_rHaSysConfig;
}

int HaGetRuleNumber(char* pRuleComment)
{
	char chCmdBuffer[256];
	char chOutPut[64] = { 0 };
	
	snprintf(chCmdBuffer, 256, "iptables -w -L -v -n --line-numbers | grep %s | awk '{print $1}'", pRuleComment);
	cmd_system_getout(chCmdBuffer, chOutPut, 64);
	
	return atoi(chOutPut);
}

BOOL CheckBusinessInif()
{
	BOOL bLinkOK = TRUE;
	FILE* hFile = fopen("/etc/gap/businessinif.conf", "r");
	if (hFile == NULL)
	{
		return bLinkOK;
	}
		
	int  nLength = 0;
	char chOutPut[64] = { 0 };
	char chBuffer[260] = { 0 };
	char chCmdBuffer[260] = { 0 };

	while (!feof(hFile))
	{
		if (!fgets(chBuffer, sizeof(chBuffer), hFile))
		{
			break;
		}
		
		nLength = strlen(chBuffer);
		chBuffer[nLength - 1] = 0x00;
		chBuffer[nLength - 2] = 0x00;
		
		snprintf(chCmdBuffer, 256, "check_network %s", chBuffer);
		memset(chBuffer, 0, sizeof(chBuffer));
		
		cmd_system_getout(chCmdBuffer, chOutPut, 64);
		
		if (atoi(chOutPut) == 1)
		{
			bLinkOK = FALSE;
		}
	}
	
	fclose(hFile);

	return bLinkOK;
}

void HaIptInit()
{
	int nRuleID;
	char chCmdBuffer[256] = { 0 };

	while ((nRuleID = HaGetRuleNumber("hainputaccept")) != 0)
	{
		snprintf(chCmdBuffer, sizeof(chCmdBuffer), "iptables -D DEFAULT %d", nRuleID);
		cmd_system_novty(chCmdBuffer);
	}

	snprintf(chCmdBuffer, sizeof(chCmdBuffer), "iptables -A DEFAULT -i %s -j ACCEPT -m comment --comment hainputaccept", g_rHaSysConfig.chIntface);
	cmd_system_novty(chCmdBuffer);
}

void* StartHaListen(void* pArg)
{
	HaBaseMgr* pHaBaseMgr = (HaBaseMgr*)pArg;

	/* open semphere */
	pHaBaseMgr->ha_mutex = sem_open(HA_SHM_SEMPHERE_NAM, O_CREAT, 0644, 0);
	if (pHaBaseMgr->ha_mutex == SEM_FAILED)
	{
		HA_LOG_ERROR("open semphere %s fail.\n", HA_SHM_SEMPHERE_NAM);
		sem_unlink(HA_SHM_SEMPHERE_NAM);
		return NULL;
	}

	int nForceFlag = 0;
	int nHaInitState = 0;
	int nPriority = 0;
	int nStartRead = 0;
	HaFaultNotifyMsg* pNotifyMsg;
	
	while (TRUE)
	{
		nForceFlag = 0;

		/* wait last register APP to post semphere */
		/***********************************************
		以下几种情况调用sem_post
		    1、HaAgent注册成功
			2、通过Web界面设置双机热备参数
			3、通过takeover进行和备切换
			4、备机心跳检测判断主机故障或两台设备状态相同
			5、接收能重新进行主备选举的消息
			6、内外端机状态变化需要进行主备选举
				 1) 内外端连接成功 InnerConnectOuter OutOnAccept
				 2）内外端状态不相同 (当HA主备状态切换时，通知对端进行切换 InoutStateChangeCallback)
				 3）内外端状态通知   InoutAddHosts
		***********************************************/
		sem_wait(pHaBaseMgr->ha_mutex);

		nHaInitState = HaGetLocalState();
		nPriority = HaGetLocalPriority();

		/* update running state */
		HA_STATE_GO_OOS;
						
		if (!nStartRead)
		{
			HaStartRead(pHaBaseMgr);
			nStartRead = 1;
			HA_LOG_DEBUG("ready to receive HA pkt ...\n");
		}

		pNotifyMsg = HaGetElectionFaultNotifyMsg();
		if (pNotifyMsg->nHaState == HA_STATE_ACT)
		{
			//要设置为ACT
			nForceFlag = HA_FLAG_FORCE_ACT;

			//设置另一台设备为STB
			pNotifyMsg->nHaState = HA_STATE_STB;
		}
		else if (pNotifyMsg->nHaState == HA_STATE_STB)
		{
			//要设置为STB
			nForceFlag = HA_FLAG_FORCE_STB;

			//设置另一台设备为ACT
			pNotifyMsg->nHaState = HA_STATE_ACT;
		}
		else
		{
			//其它情况nForceFlag为0,对方设备优先（对方状态不变），本设备为相对的状态（对方为主，本方为备，对方为备，本方为主）。
		}
		
		//发送广播消息进行主机选举
		HaElectionRequest(nHaInitState, nPriority, nForceFlag, &g_rBcastHost, pNotifyMsg);
		memset(pNotifyMsg, 0, sizeof(*pNotifyMsg));
	}
	
	/* close and unlink semphere */
	sem_close(pHaBaseMgr->ha_mutex);
	pHaBaseMgr->ha_mutex = NULL;
	sem_unlink(HA_SHM_SEMPHERE_NAM);
	
	return NULL;
}

int StartHa()
{
	pthread_t nThreadID = 0;
	pthread_create(&nThreadID, NULL, StartHaListen, g_pHaBaseMgr);
	
	return 0;
}

HaErrorCode HaSetInterface(const char* pIfname)
{	
	/*  check interface name */
	int nSocketFd = socket(AF_INET, SOCK_STREAM, 0);
	
	struct ifreq rIfreq;
	strncpy(rIfreq.ifr_name, pIfname, sizeof(rIfreq.ifr_name) - 1);
	
	if ((ioctl(nSocketFd, SIOCGIFHWADDR, &rIfreq)) < 0)
	{
		close(nSocketFd);
		return HA_ERROR_ERROR;
	}
	strncpy(g_rHaSysConfig.chIntface, pIfname, HA_MAX_INTF_NAME_LEN - 1);
	
	return HA_SUCCESS;
}

static struct HaInitFun g_rHaInitSeq[] = 
{
	{HaStateMgrInit,      NULL},
	{ha_base_mgr_init,      ha_base_mgr_deinit},		/* for base mgr */
	{ha_app_mgr_init,       NULL},						/* for application mgr */
	{ha_response_hash_init, NULL},
	{HaElectionInit,		NULL},						/* for election */
	{ha_heartbeat_init,     NULL},
	{ha_conf_init,			NULL},
	{ha_sync_mgr_init,      ha_sync_mgr_deinit},
	{ipm_init,				NULL},
	{ha_conf_cmds_mem_init, ha_conf_cmds_mem_deinit}
};

static int g_nInitFunCount = sizeof(g_rHaInitSeq) / sizeof(struct HaInitFun);

void HaDeinit()
{
	int i = g_nInitFunCount - 1;
	for (; i > 0; i--)
	{
		if (g_rHaInitSeq[i].deinit)
		{
			g_rHaInitSeq[i].deinit();
		}			
	}
}

HaErrorCode HaInit()
{
	int i = 0;
	HaErrorCode nReturn;
	for (; i < g_nInitFunCount; i++)
	{
		nReturn = g_rHaInitSeq[i].init();
		if (nReturn != HA_SUCCESS) 
		{
			HA_LOG_ERROR("init %d return %s(%d)", i, ha_error_to_str(nReturn), nReturn);
			goto FAIL;
		}
	}

	return nReturn;
	
FAIL:
	HaDeinit();

	return nReturn;
}