#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "app_common.h"
#include "bitops.h"
#include "thread.h"
#include "command.h"
#include "sockunion.h"
#include "util-lock.h"

#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_election.h"
#include "ha_statemgr.h"
#include "ha_conf.h"
#include "ha_inout.h"

#define HA_CONF_CMDS_FORMAT "set state %s\nset priority %d\nset ip %s mask %s port %d\nwrite file"

HaInoutPacket g_rInoutPacket;

HaConfigureCmds* g_pHaConfCmds[HA_MACHINE_MAX] = { NULL };

DEFUN(_ha_use_interface,
	ha_use_interface_cmd,
	"use interface WORD",
	"use\n"
	"interface\n"
	"name\n")
{
	if (HaSetInterface(argv[0]) != HA_SUCCESS)
	{
		vty_out(vty, "interface %s not exist.%s", argv[0], VTY_NEWLINE);
	}
	
	return CMD_SUCCESS;
}

DEFUN(_ha_set_ipaddr_port,
	ha_set_ipaddr_port_cmd,
	"set ip A.B.C.D mask A.B.C.D port <1024-65535>",
	"set\n"
	"ip\n"
	"address\n"
	"net mask\n"
	"address\n"
	"port\n"
	"number\n")
{
	uint16_t nPort = atoi(argv[2]);

	HaSetIPPort(argv[0], argv[1], nPort);

	return CMD_SUCCESS;
}

DEFUN(_ha_set_state,
	ha_set_state_cmd,
	"set state (activate|standby)",
	SET_STR
	"HA init state\n"
	"active\n"
	"standby\n")
{
	if (strncmp(argv[0], "activate", strlen("activate")) == 0)
	{
		HaSetInitState(HA_STATE_ACT);
	}
	else
	{
		HaSetInitState(HA_STATE_STB);
	}

	return CMD_SUCCESS;
}

DEFUN(_ha_set_priority,
	ha_set_priority_cmd,
	"set priority <1-254>",
	SET_STR
	"HA election priority\n"
	"priority value\n")
{
	int nPriority = atoi(argv[0]);
	HaSetPriority(nPriority);
	
	return  CMD_SUCCESS;
}

void SaveHaConfigurations()
{
	int nRole = 0;
	for (nRole = HA_LOCAL_INNER; nRole < HA_MACHINE_MAX; nRole++)
	{
		g_pHaConfCmds[nRole]->nMachineExist = 0;
	}
	
	struct in_addr rAddr;
	struct in_addr rMaskAddr;
	
	rAddr.s_addr = HaGetLocalIP();
	rMaskAddr.s_addr = HaGetLocalMask();

	int nLength = 0;
	char chMask[32] = { 0 };
	inet_ntop(AF_INET, &rMaskAddr, chMask, sizeof(chMask));
	
	if (g_nBoardType == BOARDTYPE_IN)
	{	
		g_pHaConfCmds[HA_LOCAL_INNER]->nMachineRole = HA_LOCAL_INNER;
		g_pHaConfCmds[HA_LOCAL_INNER]->nMachineExist = 1;
		
		nLength = snprintf(g_pHaConfCmds[HA_LOCAL_INNER]->chCmds,
			HA_CONF_CMD_LEN,
			HA_CONF_CMDS_FORMAT,
			HaGetLocalState() == HA_STATE_ACT ? "activate" : "standby",
			HaGetLocalPriority(),
			inet_ntoa(rAddr),
			chMask,
			HaGetLocalPort());
		g_pHaConfCmds[HA_LOCAL_INNER]->chCmds[nLength] = 0;
		
		HA_LOG_DEBUG("role: %d %s\n", HA_LOCAL_INNER, g_pHaConfCmds[HA_LOCAL_INNER]->chCmds);


		//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
		memset(&g_pHaBaseMgr->rHaHostArray[0], 0, sizeof(HaHost));
	}
	else
	{
		g_pHaConfCmds[HA_LOCAL_OUTER]->nMachineRole = HA_LOCAL_OUTER;
		g_pHaConfCmds[HA_LOCAL_OUTER]->nMachineExist = 1;
		
		nLength = snprintf(g_pHaConfCmds[HA_LOCAL_OUTER]->chCmds,
			HA_CONF_CMD_LEN,
			HA_CONF_CMDS_FORMAT,
			HaGetLocalState() == HA_STATE_ACT ? "activate" : "standby",
			HaGetLocalPriority(),
			inet_ntoa(rAddr),
			chMask,
			HaGetLocalPort());
		g_pHaConfCmds[HA_LOCAL_OUTER]->chCmds[nLength] = 0;
		
		HA_LOG_DEBUG("role : %d % s\n", HA_LOCAL_OUTER, g_pHaConfCmds[HA_LOCAL_OUTER]->chCmds);

		memset(&g_pHaBaseMgr->rHaHostArray[1], 0, sizeof(HaHost));
	}	
		
	int i = 0;
	HaHost* pHaHost = NULL;	
	
	for (; i < 4; i++)
	{
		pHaHost = &g_pHaBaseMgr->rHaHostArray[i];
		if (pHaHost->rAddr.sin_addr.s_addr == 0)
		{
			continue;
		}
		
		if(pHaHost->nHostType == 3)//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
		{
			nRole = HA_PEER_INNER;
		}
		else if(pHaHost->nHostType == 4)
		{
			nRole = HA_PEER_OUTER;
		}	
		else
		{
			if (g_nBoardType == BOARDTYPE_IN)
			{
				if (pHaHost->nHostType == 2)
				{
					nRole = HA_LOCAL_OUTER;
				}
				else
				{
					continue;
				}
			}
			else
			{
				if (pHaHost->nHostType == 1)
				{
					nRole = HA_LOCAL_INNER;
				}
				else
				{
					continue;
				}
			}
		}

		g_pHaConfCmds[nRole]->nMachineRole = nRole;
		g_pHaConfCmds[nRole]->nMachineExist = 1;
		
		rMaskAddr.s_addr = pHaHost->dwMask;
		memset(chMask, 0, sizeof(chMask));
		inet_ntop(AF_INET, &rMaskAddr, chMask, sizeof(chMask));
		
		nLength = snprintf(g_pHaConfCmds[nRole]->chCmds, HA_CONF_CMD_LEN,
			HA_CONF_CMDS_FORMAT,
			pHaHost->nInitState == HA_STATE_ACT ? "activate" : "standby",
			pHaHost->nPriority,
			inet_ntoa(pHaHost->rAddr.sin_addr),
			chMask,
			HaGetLocalPort());
		g_pHaConfCmds[nRole]->chCmds[nLength] = 0;
		
		HA_LOG_DEBUG("role: %d %s\n", nRole, g_pHaConfCmds[nRole]->chCmds);
	}
}

void SaveLocalConfigurationCmds(const char* pCmds, int nLength)
{
	if (g_nBoardType == BOARDTYPE_IN)
	{
		memset(g_pHaConfCmds[HA_LOCAL_INNER]->chCmds, 0, HA_CONF_CMD_LEN);
		memcpy(g_pHaConfCmds[HA_LOCAL_INNER]->chCmds, pCmds, nLength);
	}
	else
	{
		memset(g_pHaConfCmds[HA_LOCAL_OUTER]->chCmds, 0, HA_CONF_CMD_LEN);
		memcpy(g_pHaConfCmds[HA_LOCAL_OUTER]->chCmds, pCmds, nLength);
	}
}

void ApplyLocalConfigurationCmds()
{
	char* pCmd = NULL;
	char* pNext = NULL;
	FILE* fpRead = NULL;
	
	char chBuffer[128] = { 0 };
	char cmds[HA_CONF_CMD_LEN] = { 0 };	

	if (g_nBoardType == BOARDTYPE_IN)
	{
		strcpy(cmds, g_pHaConfCmds[HA_LOCAL_INNER]->chCmds);
	}
	else
	{
		strcpy(cmds, g_pHaConfCmds[HA_LOCAL_OUTER]->chCmds);
	}

	char* pCommands = cmds;
	
	for (pCmd = strtok_r(pCommands, "\n", &pNext); pCmd != NULL; pCmd = strtok_r(NULL, "\n", &pNext))
	{
		HA_LOG_DEBUG("cmd: %s\n", pCmd);
		if (strncmp(pCmd, "write file", strlen("write file")) == 0)
		{
			snprintf(chBuffer, sizeof(chBuffer), "vtysh -c '%s'", pCmd);
		}			
		else
		{
			snprintf(chBuffer, sizeof(chBuffer), "vtysh -c 'configure terminal' -c 'ha' -c '%s'", pCmd);
		}
			
		fpRead = popen(chBuffer, "r");
		if (fpRead == NULL)
		{
			SCLogError("vty command %s Failed\n", chBuffer);
			return;
		}
		
		while (fgets(chBuffer, sizeof(chBuffer), fpRead) != NULL)
		{
			if ((strstr(chBuffer, "Command success") == NULL) && (strncmp(pCmd, "write file", strlen("write file")) != 0))
			{
				SCLogError("%s\n", chBuffer);
				pclose(fpRead);
				fpRead = NULL;
				return;
			}
		}
		pclose(fpRead);
		fpRead = NULL;

		memset(chBuffer, 0, sizeof(chBuffer));
	}
}

static int SendMsgToAllMachine(HaConfMsgType nMsgType)
{
	int nRole;
	int nReturn = 0;
	
	HaConfMsg* pConfigMsg = &g_rInoutPacket.u.rConfigMsg;

	memset(&g_rInoutPacket, 0, sizeof(HaInoutPacket));
	pConfigMsg->nMsgType = nMsgType;

	for (nRole = HA_PEER_OUTER; nRole >= HA_LOCAL_INNER; nRole--)
	{
		HA_LOG_DEBUG("role: %d, machine_exist: %d\n", nRole, g_pHaConfCmds[nRole]->nMachineExist);
		if (!g_pHaConfCmds[nRole]->nMachineExist)
		{
			continue;
		}			

		if (HA_CONF_MSG_CONFIGURATION_CMDS == nMsgType)
		{
			pConfigMsg->nLength = strlen(g_pHaConfCmds[nRole]->chCmds) + 1;
			memcpy(pConfigMsg->chData, g_pHaConfCmds[nRole]->chCmds, pConfigMsg->nLength);
		}

		switch (nRole)
		{
		case HA_PEER_OUTER:
			/* send msg to peer outer */
			if (!g_pHaConfCmds[HA_PEER_OUTER]->nMachineExist || !g_pHaConfCmds[HA_PEER_INNER]->nMachineExist)
			{
				break;
			}
				
			pConfigMsg->nPeerOuter = 1;
			HA_LOG_DEBUG("send msg %d to peer outer\n", nMsgType);
			
			if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
			{
				nReturn = HA_CMD_CONFIG_STB_OUTER_ERR;
				goto error;
			}
			break;
			
		case HA_PEER_INNER:
			/* send msg to peer inner */
			if (!g_pHaConfCmds[HA_PEER_OUTER]->nMachineExist || !g_pHaConfCmds[HA_PEER_INNER]->nMachineExist)
			{
				break;
			}
				
			pConfigMsg->nPeerOuter = 0;
			HA_LOG_DEBUG("send msg %d to peer inner\n", nMsgType);
			if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
			{
				nReturn = HA_CMD_CONFIG_STB_INNER_ERR;
				goto error;
			}
			break;
			
		case HA_LOCAL_OUTER:
			/* send msg to local outer */
			g_rInoutPacket.nType = HA_INOUT_PACKET_NOTIFY;
			g_rInoutPacket.nMsgID = HA_INOUT_CONF_MSG;
			HA_LOG_DEBUG("send msg %d to loal outer\n", nMsgType);

			if (InoutSend(&g_rInoutPacket, sizeof(g_rInoutPacket)) != HA_SUCCESS)
			{
				nReturn = HA_CMD_CONFIG_ACT_OUTER_ERR;
				HA_LOG_DEBUG("send msg %d to loal outer fail!\n", nMsgType);

				goto error;
			}
			break;
			
		case HA_LOCAL_INNER:
			if (HA_CONF_MSG_CONFIGURATION_CMDS == nMsgType)
			{
				HA_LOG_DEBUG("%s\n", g_pHaConfCmds[HA_LOCAL_INNER]->chCmds);
			}
			else if (HA_CONF_MSG_CLOSE_SOCKET == nMsgType)
			{
				HA_LOG_DEBUG("close sync socket ...\n");
				HaEventNotify(HA_EVENT_CONF_CLOSE_SOCKET, NULL, 0);
			}
			else if (HA_CONF_MSG_RECOVER == nMsgType)
			{
				HA_LOG_DEBUG("recover ...\n");
								
				struct in_addr rIPAddr;
				struct in_addr rMaskAddr;
				
				rIPAddr.s_addr = g_pHaConfCmds[HA_LOCAL_INNER]->dwIP;								
				rMaskAddr.s_addr = g_pHaConfCmds[HA_LOCAL_INNER]->dwMask;
				
				char chMask[32] = { 0 };
				inet_ntop(AF_INET, &rMaskAddr, chMask, sizeof(chMask));
				
				HaSetInitState(g_pHaConfCmds[HA_LOCAL_INNER]->nInitState);
				HaSetIPPort(inet_ntoa(rIPAddr), chMask, g_pHaConfCmds[HA_LOCAL_INNER]->nPort);
				HaSetPriority(g_pHaConfCmds[HA_LOCAL_INNER]->nPriority);
				usleep(500 * 1000);

				HaEventNotify(HA_EVENT_CONF_RECOVER, NULL, 0);
			}
			else
			{
				HA_LOG_ERROR("unknown msg type %d ...\n", nMsgType);
			}				
			break;
			
		default:
			break;
		}
	}

error:
	return nReturn;
}

static int SendMsgToStopTimers()
{
	int nReturn = 0;
	HaConfMsg* pConfigMsg = &g_rInoutPacket.u.rConfigMsg;

	memset(&g_rInoutPacket, 0, sizeof(HaInoutPacket));
	pConfigMsg->nMsgType = HA_CONF_MSG_STOP_TIMER;

	/* tell local inner stop timer */
	HA_LOG_DEBUG("stop timer ...\n");
	HaEventNotify(HA_EVENT_CONF_STOP_TIMER, NULL, 0);

	/* send msg to local outer */
	g_rInoutPacket.nType = HA_INOUT_PACKET_NOTIFY;
	g_rInoutPacket.nMsgID = HA_INOUT_CONF_MSG;
	if (InoutSend(&g_rInoutPacket, sizeof(g_rInoutPacket)) != HA_SUCCESS)
	{
		nReturn = HA_CMD_CONFIG_ACT_OUTER_ERR;
		goto error;
	}

	if (!g_pHaConfCmds[HA_PEER_OUTER]->nMachineExist || !g_pHaConfCmds[HA_PEER_INNER]->nMachineExist)
	{
		goto error;
	}
		
	/* send msg to peer inner */
	pConfigMsg->nPeerOuter = 0;
	if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
	{
		nReturn = HA_CMD_CONFIG_STB_INNER_ERR;
		goto error;
	}

	/* send msg to peer outer */
	pConfigMsg->nPeerOuter = 1;
	if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
	{
		nReturn = HA_CMD_CONFIG_STB_OUTER_ERR;
		goto error;
	}

error:
	return nReturn;
}

static int SendMsgToCloseSocket()
{
	int nReturn = 0;
	HaConfMsg* pConfigMsg = &g_rInoutPacket.u.rConfigMsg;

	memset(&g_rInoutPacket, 0, sizeof(HaInoutPacket));
	pConfigMsg->nMsgType = HA_CONF_MSG_CLOSE_SOCKET;

	/* tell local outer to close sync socket */
	g_rInoutPacket.nType = HA_INOUT_PACKET_NOTIFY;
	g_rInoutPacket.nMsgID = HA_INOUT_CONF_MSG;
	if (InoutSend(&g_rInoutPacket, sizeof(g_rInoutPacket)) != HA_SUCCESS)
	{
		nReturn = HA_CMD_CONFIG_ACT_OUTER_ERR;
		goto error;
	}

	/* tell local inner to close sync socket */
	HA_LOG_DEBUG("close sync socket ...\n");
	HaEventNotify(HA_EVENT_CONF_CLOSE_SOCKET, NULL, 0);

	if (!g_pHaConfCmds[HA_PEER_OUTER]->nMachineExist
		|| !g_pHaConfCmds[HA_PEER_INNER]->nMachineExist)
	{
		goto error;
	}
		
	/* tell peer outer to close sync socket */
	pConfigMsg->nPeerOuter = 1;
	if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
	{
		nReturn = HA_CMD_CONFIG_STB_OUTER_ERR;
		goto error;
	}

	/* tell peer inner to close sync socket */
	pConfigMsg->nPeerOuter = 0;
	if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
	{
		nReturn = HA_CMD_CONFIG_STB_INNER_ERR;
		goto error;
	}

error:
	return nReturn;
}

static int SendMsgToTellPeerGoOos()
{
	int nReturn = 0;
	HaConfMsg* pConfigMsg = &g_rInoutPacket.u.rConfigMsg;

	memset(&g_rInoutPacket, 0, sizeof(HaInoutPacket));
	pConfigMsg->nMsgType = HA_CONF_MSG_GO_OOS;

	/* tell peer outer to go oos */
	pConfigMsg->nPeerOuter = 1;
	if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
	{
		nReturn = HA_CMD_CONFIG_STB_OUTER_ERR;
		goto error;
	}

	/* tell peer inner to go oos */
	pConfigMsg->nPeerOuter = 0;
	if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
	{
		nReturn = HA_CMD_CONFIG_STB_INNER_ERR;
		goto error;
	}

error:
	return nReturn;
}

static int SendMsgToReElection()
{
	/* firstly tell peer go oos */
	int nReturn = SendMsgToTellPeerGoOos();
	if (nReturn)
	{
		goto error;
	}		
	usleep(200 * 1000);

	HaConfMsg* pConfigMsg = &g_rInoutPacket.u.rConfigMsg;
	
	memset(&g_rInoutPacket, 0, sizeof(HaInoutPacket));
	pConfigMsg->nMsgType = HA_CONF_MSG_REELECTION;

	/* tell local outer to reelection */
	g_rInoutPacket.nType = HA_INOUT_PACKET_NOTIFY;
	g_rInoutPacket.nMsgID = HA_INOUT_CONF_MSG;
	
	if (InoutSend(&g_rInoutPacket, sizeof(g_rInoutPacket)) != HA_SUCCESS)
	{
		nReturn = HA_CMD_CONFIG_ACT_OUTER_ERR;
		goto error;
	}

	/* tell local inner to reelection */
	sem_post(g_pHaBaseMgr->ha_mutex);

	/* wait local machine reelection done, if local state isn't ACT, tell peer reelection */
	usleep(500 * 1000);
	
	if (HaGetLocalRunningState() != HA_STATE_ACT)
	{
		/* tell peer outer to reelection */
		pConfigMsg->nPeerOuter = 1;
		if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
		{
			nReturn = HA_CMD_CONFIG_STB_OUTER_ERR;
			goto error;
		}

		/* tell peer inner to reelection */
		pConfigMsg->nPeerOuter = 0;
		if (HaSendConfigData((char*)pConfigMsg, sizeof(HaConfMsg)) < 0)
		{
			nReturn = HA_CMD_CONFIG_STB_INNER_ERR;
			goto error;
		}
	}
	
error:
	return nReturn;
}

DEFUN(_ha_set_conf_from_web,
	ha_set_conf_from_web_cmd,
	"set (local|peer) (inner|outer) state (activate|standby) priority <1-254> ip A.B.C.D mask A.B.C.D port <1024-65535>",
	SET_STR
	"local machine\n"
	"peer machine\n"
	"inner host\n"
	"outer host\n"
	"HA init state\n"
	"active\n"
	"standby\n"
	"HA election priority\n"
	"priority value\n"
	"ip\n"
	"address\n"
	"net mask\n"
	"address\n"
	"ha port\n"
	"number\n"
	"data sync port\n"
	"number\n")
{
	/**********************************************************************************************
	*If there are act and stb two machines, this cmd will be called 4 times for peer outer,
	*peer inner, local outer, local inner.
	*If there is only one machine, this cmd will be called 2 times for local outer, local inner.
	*And, the cmd for local inner is always the last cmd.
	***********************************************************************************************/

	int nRole;
	if (strncmp(argv[0], "local", strlen("local")) == 0)
	{
		if (strncmp(argv[1], "inner", strlen("inner")) == 0)
		{
			nRole = HA_LOCAL_INNER;
		}			
		else
		{
			nRole = HA_LOCAL_OUTER;
		}			
	}
	else
	{
		if (strncmp(argv[1], "inner", strlen("inner")) == 0)
		{
			nRole = HA_PEER_INNER;
		}			
		else
		{
			nRole = HA_PEER_OUTER;
		}			
	}

	if (strncmp(argv[2], "activate", strlen("activate")) == 0)
	{
		g_pHaConfCmds[nRole]->nInitState = HA_STATE_ACT;
	}		
	else
	{
		g_pHaConfCmds[nRole]->nInitState = HA_STATE_STB; 
	}
		
	g_pHaConfCmds[nRole]->nPriority = atoi(argv[3]);
	g_pHaConfCmds[nRole]->dwIP = inet_addr(argv[4]);
	g_pHaConfCmds[nRole]->dwMask = inet_addr(argv[5]);
	g_pHaConfCmds[nRole]->nPort = atoi(argv[6]);
	
	char chCmd[HA_CONF_CMD_LEN] = { 0 };
	int nLength = snprintf(chCmd, sizeof(chCmd), HA_CONF_CMDS_FORMAT,
		argv[2],
		atoi(argv[3]),
		argv[4], argv[5], atoi(argv[6]));

	HA_LOG_DEBUG("argv[4]: %s, argv[5]: %s\n", argv[4], argv[5]);
	HA_LOG_DEBUG("ip: %08x, mask: %08x\n", g_pHaConfCmds[nRole]->dwIP, g_pHaConfCmds[nRole]->dwMask);
	
	static int nHaConfCmdsModified = 0;
	
	if (g_pHaConfCmds[nRole]->nMachineExist
		&& (strncmp(g_pHaConfCmds[nRole]->chCmds, chCmd, nLength) != 0))
	{
		memcpy(g_pHaConfCmds[nRole]->chCmds, chCmd, nLength);
		g_pHaConfCmds[nRole]->chCmds[nLength] = 0;
		nHaConfCmdsModified = 1;
	}

	/* if not local inner, return */
	if (nRole != HA_LOCAL_INNER)
	{
		return CMD_SUCCESS;
	}

	/* local inner recv last cmd from web,if ha configure never changed, return */
	if (!nHaConfCmdsModified)
	{
		return CMD_SUCCESS;
	}
	nHaConfCmdsModified = 0;

	/* if local and peer ip are not same segment, return */
	if (g_pHaConfCmds[HA_PEER_OUTER]->nMachineExist && g_pHaConfCmds[HA_PEER_INNER]->nMachineExist)
	{
		//对方设备存在
		if (((g_pHaConfCmds[HA_LOCAL_INNER]->dwIP & g_pHaConfCmds[HA_LOCAL_INNER]->dwMask)
			!= (g_pHaConfCmds[HA_PEER_INNER]->dwIP & g_pHaConfCmds[HA_PEER_INNER]->dwMask))
			|| ((g_pHaConfCmds[HA_LOCAL_OUTER]->dwIP & g_pHaConfCmds[HA_LOCAL_OUTER]->dwMask)
				!= (g_pHaConfCmds[HA_PEER_OUTER]->dwIP & g_pHaConfCmds[HA_PEER_OUTER]->dwMask)))
		{
			vty_out(vty, "set ha config failed %s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	/* IF local ip is the same with peer ip, return */
	if ((g_pHaConfCmds[HA_LOCAL_INNER]->dwIP == g_pHaConfCmds[HA_PEER_INNER]->dwIP)
		|| (g_pHaConfCmds[HA_LOCAL_OUTER]->dwIP == g_pHaConfCmds[HA_PEER_OUTER]->dwIP))
	{
		vty_out(vty, "ip conflict%s", VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	//HA_LOG_DEBUG("call SendMsgToStopTimers!\n");
	/* stop all heartbeat timer and inout timer */
	int nReturn = SendMsgToStopTimers();
	if (nReturn)
	{
		g_pHaBaseMgr->bStopTimer = FALSE;
		goto error;
	}		
	usleep(500 * 1000);

	//HA_LOG_DEBUG("call SendMsgToCloseSocket!\n");
	/* tell local machines close sync socket */
	nReturn = SendMsgToCloseSocket();
	if (nReturn)
	{
		g_pHaBaseMgr->bStopTimer = FALSE;
		goto error;
	}	
	usleep(500 * 1000);

	//HA_LOG_DEBUG("call SendMsgToAllMachine HA_CONF_MSG_CONFIGURATION_CMDS!\n");
	/* send configuration msg to all machines */
	nReturn = SendMsgToAllMachine(HA_CONF_MSG_CONFIGURATION_CMDS);
	if (nReturn)
	{
		g_pHaBaseMgr->bStopTimer = FALSE;
		goto error;
	}	
	usleep(500 * 1000);

	//HA_LOG_DEBUG("call SendMsgToAllMachine HA_CONF_MSG_RECOVER!\n");
	/* tell all machines rebuild socket, and tell inner restart inout_timer */
	nReturn = SendMsgToAllMachine(HA_CONF_MSG_RECOVER);
	if (nReturn)
	{
		g_pHaBaseMgr->bStopTimer = FALSE;
		goto error;
	}	
	usleep(500 * 1000);

	/* tell local outer and local inner to reelection */
	if (g_pHaConfCmds[HA_PEER_OUTER]->nMachineExist
		&& g_pHaConfCmds[HA_PEER_INNER]->nMachineExist)
	{
		//HA_LOG_DEBUG("call SendMsgToReElection!\n");
		nReturn = SendMsgToReElection();
		if (nReturn)
		{
			g_pHaBaseMgr->bStopTimer = FALSE;
			goto error;
		}			
	}

	g_pHaBaseMgr->bStopTimer = FALSE;

	return CMD_SUCCESS;
	
error:
	vty_out(vty, "set ha config from web failed %s", VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(_ha_set_auto_failback,
	ha_set_auto_failback_cmd,
	"(enable|disable) auto failback",
	"enable some feature\n"
	"disable some feature\n"
	"auto\n"
	"fail back for Active\n")
{
	if (strncmp(argv[0], "enable", strlen("enable")) == 0)
	{
		HaAutoFailbackEnable();
	}
	else
	{
		HaAutoFailbackDisable();
	}
	
	return CMD_SUCCESS;
}

DEFUN(_ha_set_hb_time,
	ha_set_hb_time_cmd,
	"set heartbeat time interval WORD wait WORD",
	SET_STR
	"HA heartbeat\n"
	"time\n"
	"ACT host wait heartbeat response timeout\n"
	"value\n"
	"ACT host send heartbeat and STB host wait heartbeat timeout\n"
	"value\n")
{
	uint32_t nIntervalTime = (uint32_t)atoi(argv[0]);
	uint32_t nWaitTime = (uint32_t)atoi(argv[1]);

	HaSetHeartbeatTime(nIntervalTime, nWaitTime);
	
	return  CMD_SUCCESS;
}

char* HaStrTime(time_t* pTime)
{
	static char chBuffer[128];
	memset(chBuffer, 0, 128);
	
	struct tm* pTimeinfo = localtime(pTime);
	strftime(chBuffer, 128, "%F %T", pTimeinfo);
	
	return chBuffer;
}

static char* GetHostStateStr(HaHost* pHaHost)
{
	int nLength = 0;
	static char chBuffer[12];	
	memset(chBuffer, 0, sizeof(chBuffer));
	
	if (pHaHost->nOnTime > 0)
	{
		nLength += snprintf(&chBuffer[nLength], 12, "%s", "O");
	}
	
	if (pHaHost->nRunningState == HA_STATE_ACT)
	{
		nLength += snprintf(&chBuffer[nLength], 12, "%s", "A");
	}
	else if (pHaHost->nRunningState == HA_STATE_STB)
	{
		nLength += snprintf(&chBuffer[nLength], 12, "%s", "S");
	}		
	
	//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
	if( (pHaHost->nHostType == 1) || (pHaHost->nHostType == 3) )
	{
		nLength += snprintf(&chBuffer[nLength], 12, "%s", "I");
	}
	else if( (pHaHost->nHostType == 2) || (pHaHost->nHostType == 4) )
	{
		nLength += snprintf(&chBuffer[nLength], 12, "%s", "U");
	}		

	return chBuffer;
}

DEFUN(_ha_show_state,
	ha_show_state_cmd,
	"show ha state",
	SHOW_STR
	"HA state\n")
{	
	SaveHaConfigurations();
	
	int nPeerExist = 0;
	if (g_pHaConfCmds[HA_PEER_OUTER]->nMachineExist && g_pHaConfCmds[HA_PEER_INNER]->nMachineExist)
	{
		nPeerExist = 1;
	}
		
	struct in_addr rAddr;
	struct in_addr rMaskAddr;
	
	rAddr.s_addr = HaGetLocalIP();
	rMaskAddr.s_addr = HaGetLocalMask();
	
	vty_out(vty, "init state    : %s%s", ha_state_to_str(HaGetLocalState()), VTY_NEWLINE);
	vty_out(vty, "init priority : %d%s", HaGetLocalPriority(), VTY_NEWLINE);
	vty_out(vty, "running state : %s%s", ha_state_to_str(HaGetLocalRunningState()), VTY_NEWLINE);
	vty_out(vty, "local ip      : %s%s", inet_ntoa(rAddr), VTY_NEWLINE);
	vty_out(vty, "local mask    : %s%s", inet_ntoa(rMaskAddr), VTY_NEWLINE);
	vty_out(vty, "local port    : %d%s", HaGetLocalPort(), VTY_NEWLINE);
	vty_out(vty, "peer exist    : %s%s", nPeerExist ? "yes" : "no", VTY_NEWLINE);

	if (g_pHaBaseMgr->rHaHostArray[0].rAddr.sin_addr.s_addr == 0)
	{
		if (g_pHaBaseMgr->rHaHostArray[1].rAddr.sin_addr.s_addr == 0)
		{
			if (g_pHaBaseMgr->rHaHostArray[2].rAddr.sin_addr.s_addr == 0)
			{
				if (g_pHaBaseMgr->rHaHostArray[3].rAddr.sin_addr.s_addr == 0)
				{
					return CMD_SUCCESS;
				}
			}
		}
	}
		
	vty_out(vty, "other host  : %s", VTY_NEWLINE);
	vty_out(vty, "        %-16s%-16s%-8s%-12s%-18s%-12s%-20s%-20s%-s", "ip", "mask", "flags", "init_state",
		"running_state", "priority", "up time", "down time", VTY_NEWLINE);
	
	int  i = 0;
	int  nLength = 0;
	char chMask[32] = { 0 };
	char chBuffer[1024] = { 0};
	HaHost* pHaHost = NULL;
	
	for (; i < 4; i++)
	{
		pHaHost = &g_pHaBaseMgr->rHaHostArray[i];
		if (pHaHost->rAddr.sin_addr.s_addr == 0)
		{
			continue;
		}

		rMaskAddr.s_addr = pHaHost->dwMask;
		memset(chMask, 0, sizeof(chMask));
		inet_ntop(AF_INET, &rMaskAddr, chMask, sizeof(chMask));
		
		nLength = sprintf(chBuffer, "        %-16s%-16s%-8s%-12s%-18s%-12d%-20s",
			inet_ntoa(pHaHost->rAddr.sin_addr),
			chMask,
			GetHostStateStr(pHaHost),
			ha_state_to_str(pHaHost->nInitState),
			ha_state_to_str(pHaHost->nRunningState),
			pHaHost->nPriority,
			pHaHost->nOnTime ? HaStrTime(&pHaHost->nOnTime) : "");
		
		nLength += sprintf(&chBuffer[nLength], "%-20s",
			pHaHost->nOffTime ? HaStrTime(&pHaHost->nOffTime) : "");
		vty_out(vty, "%s%s", chBuffer, VTY_NEWLINE);
	}
	
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "\tO-online A-Active S-standby I-inner U-outer%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}
 
DEFUN(_ha_takeover,
	ha_takeover_cmd,
	"takeover",
	"for HA state change, reelection\n")
{
	HaFaultNotifyMsg rNotifyMsg;
	HaState nRunningState = HaGetLocalRunningState();
	
	if (nRunningState == HA_STATE_ACT)
	{
		rNotifyMsg.nHaState = HA_STATE_STB;
	}		
	else if (nRunningState == HA_STATE_STB)
	{
		rNotifyMsg.nHaState = HA_STATE_ACT;
	}	
	else if (nRunningState == HA_STATE_OOS)
	{
		rNotifyMsg.nHaState = HA_STATE_STB;
	}
	else
	{
		vty_out(vty, "takeover failed %s", VTY_NEWLINE);
		return CMD_ERR_NOTHING_TODO;
	}

	rNotifyMsg.dwIPAddr = HaGetLocalIP();
	rNotifyMsg.nFaultState = HA_FAULT_NONE;
	HaSetElectionFaultNotifyMsg(&rNotifyMsg);

	sem_post(g_pHaBaseMgr->ha_mutex);
	vty_out(vty, "success%s", VTY_NEWLINE);
	
	return CMD_SUCCESS;
}

DEFUN(_ha_enter,
	ha_enter_cmd,
	"ha",
	"Enter HA configuration\n"
)
{
	vty->node = HA_NODE;
	return CMD_SUCCESS;
}

static struct cmd_node ha_node =
{
	HA_NODE,
	"%s(ha)#",
	1,
	NULL,
	NULL
};

static int ha_config_write(struct vty* vty)
{
	int nWrite = 0;
	HaSysConfig* pSysConfig = HaGetConfig();

	vty_out(vty, "ha%s", VTY_NEWLINE);
	nWrite++;

	vty_out(vty, "use interface %s%s", pSysConfig->chIntface, VTY_NEWLINE);
	nWrite++;

	char chMask[32] = { 0 };
	char chBuffer[128] = { 0 };
	struct in_addr rMaskAddr;	
	
	if (pSysConfig->nLocalPort)
	{
		inet_ntop(AF_INET, &pSysConfig->rLocalIPAddr, chBuffer, 128);
		rMaskAddr.s_addr = pSysConfig->dwLocalMask;
		inet_ntop(AF_INET, &rMaskAddr, chMask, 32);
		vty_out(vty, "set ip %s mask %s port %d%s",
			chBuffer,
			chMask,
			pSysConfig->nLocalPort, VTY_NEWLINE);
		nWrite++;
	}

	if (pSysConfig->nInitState == HA_STATE_ACT)
	{
		vty_out(vty, "set state activate%s", VTY_NEWLINE);
		nWrite++;
	}
	else if (pSysConfig->nInitState == HA_STATE_STB) 
	{
		vty_out(vty, "set state standby%s", VTY_NEWLINE);
		nWrite++;
	}

	vty_out(vty, "set priority %d%s", pSysConfig->nPriority, VTY_NEWLINE);
	nWrite++;
	
	/*if (pSysConfig->nAutoFailBack)
	{
		vty_out(vty, "enable auto failback%s", VTY_NEWLINE);
		nWrite++;
	}*/

	vty_out(vty, "set heartbeat time interval %d wait %d%s",
		pSysConfig->nIntervalTime,
		pSysConfig->nWaitTime, VTY_NEWLINE);
	nWrite++;

	return nWrite;
}

int ha_conf_cmds_mem_init()
{
	memset(&g_rInoutPacket, 0, sizeof(g_rInoutPacket));
	
	if (!g_pHaConfCmds[HA_LOCAL_INNER])
	{
		g_pHaConfCmds[HA_LOCAL_INNER] = SCMalloc(sizeof(HaConfigureCmds) * HA_MACHINE_MAX);
		if (!g_pHaConfCmds[HA_LOCAL_INNER])
		{
			return -HA_ERROR_NOMEM;
		}
			
		for (int i = HA_LOCAL_OUTER; i < HA_MACHINE_MAX; i++)
		{
			g_pHaConfCmds[i] = g_pHaConfCmds[HA_LOCAL_INNER] + i;
		}			
	}
	else
	{
		return HA_SUCCESS;
	}		

	memset(g_pHaConfCmds[HA_LOCAL_INNER], 0, (sizeof(HaConfigureCmds) * HA_MACHINE_MAX));
	
	return HA_SUCCESS;
}

void ha_conf_cmds_mem_deinit()
{
	if (g_pHaConfCmds[HA_LOCAL_INNER])
	{
		SCFree(g_pHaConfCmds[HA_LOCAL_INNER]);
	}		
}

void ha_cmd_init()
{
	install_node(&ha_node, ha_config_write);
	install_default(HA_NODE);

	install_element(CONFIG_NODE, &ha_enter_cmd);
	
	install_element(HA_NODE, &ha_use_interface_cmd);
	install_element(HA_NODE, &ha_set_ipaddr_port_cmd);
	install_element(HA_NODE, &ha_set_state_cmd);
	install_element(HA_NODE, &ha_set_priority_cmd);
	
	//install_element(HA_NODE, &ha_set_auto_failback_cmd);
	
	install_element(HA_NODE, &ha_set_hb_time_cmd);
	install_element(HA_NODE, &ha_takeover_cmd);
	install_element(HA_NODE, &ha_set_conf_from_web_cmd);

	install_element(VIEW_NODE, &ha_show_state_cmd);
	install_element(ENABLE_NODE, &ha_show_state_cmd);
}