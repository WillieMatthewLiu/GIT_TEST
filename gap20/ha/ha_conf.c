#include "app_common.h"
#include "command.h"
#include "util-lock.h"
#include "bitops.h"

#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_election.h"
#include "ha_statemgr.h"
#include "ha_heartbeat.h"
#include "ha_conf.h"
#include "ha_inout.h"

pthread_cond_t g_ConfigCond;
pthread_mutex_t g_ConfigMutex;

/***send broadcast configure packet.**/
int HaSendConfigData(char* pMsg, int nLength)
{
	if (!pMsg)
	{
		return -1;
	}
	
	struct timeval tvNow;
	gettimeofday(&tvNow, NULL);
	
	struct timespec tvTimeOut;	
	tvTimeOut.tv_sec = tvNow.tv_sec + HA_CONF_TIMEOUT_VAL / 1000;
	tvTimeOut.tv_nsec = 0;

	int nReturn = HaManagerSendData(HA_PACKET_REQ, HA_PAYLOAD_CONFIGURE, HaGetPktSeqAndAdd(),
		(uint8_t*)pMsg, nLength, &g_rBcastHost);
	if (nReturn == -1)
	{
		HA_LOG_ERROR("send conf request failed\n");
		return -1;
	}
	
	pthread_mutex_lock(&g_ConfigMutex);
	int status = pthread_cond_timedwait(&g_ConfigCond, &g_ConfigMutex, &tvTimeOut);
	if (status == ETIMEDOUT)
	{
		HA_LOG_ERROR("send conf request timeout\n");
		pthread_mutex_unlock(&g_ConfigMutex);
		return -1;
	}
	pthread_mutex_unlock(&g_ConfigMutex);

	return 0;
}

int HaSendConfigRespData(char* pMsg, int nLength, uint32_t nSequence, HaHost* pHaHost)
{
	int nReturn = HaManagerSendData(HA_PACKET_RESP, HA_PAYLOAD_CONFIGURE,
		nSequence, (uint8_t*)pMsg, nLength, pHaHost);
	if (nReturn == -1)
	{
		HA_LOG_ERROR("send conf response failed\n");
		return -1;
	}

	return 0;
}

/***callback hook when rcv configure request packet*/
int HaConfigReqCB(HaPktObject* pHaPktObj, HaHost* pHaHost)
{
	int nLength = pHaPktObj->nDataLen;
	HaConfMsg* pConfMsg = (HaConfMsg*)(pHaPktObj->chData);

	if (pConfMsg->nPeerOuter)
	{
		HA_LOG_DEBUG("send msg %d to outer\n", pConfMsg->nMsgType);
		
		HaInoutPacket rInoutPacket;
		memset(&rInoutPacket, 0, sizeof(HaInoutPacket));
		
		rInoutPacket.nType = HA_INOUT_PACKET_NOTIFY;
		rInoutPacket.nMsgID = HA_INOUT_CONF_MSG;
		memcpy(&rInoutPacket.u.rConfigMsg, pConfMsg, nLength);
		
		if (InoutSend(&rInoutPacket, sizeof(rInoutPacket)) != HA_SUCCESS)
		{
			return -1;
		}			
	}
	else
	{
		char* pData = pConfMsg->chData;
		
		switch (pConfMsg->nMsgType)
		{
		case HA_CONF_MSG_STOP_TIMER:
			HA_LOG_DEBUG("stop timer ...\n");
			HaEventNotify(HA_EVENT_CONF_STOP_TIMER, NULL, 0);
			break;
			
		case HA_CONF_MSG_CONFIGURATION_CMDS:			
			SaveLocalConfigurationCmds(pData, pConfMsg->nLength);
			break;
		 
		case HA_CONF_MSG_CLOSE_SOCKET:
			HA_LOG_DEBUG("close sync socket ...\n");
			HaEventNotify(HA_EVENT_CONF_CLOSE_SOCKET, NULL, 0);
			break;
			
		case HA_CONF_MSG_RECOVER:
			HA_LOG_DEBUG("recover ...\n");
			HaSendConfigRespData(pConfMsg, nLength, pHaPktObj->nSequence, pHaHost);
			ApplyLocalConfigurationCmds();
			usleep(100 * 1000);
			HaEventNotify(HA_EVENT_CONF_RECOVER, NULL, 0);
			return 0;
			
		case HA_CONF_MSG_GO_OOS:
			HA_STATE_GO_OOS;
			break;
			
		case HA_CONF_MSG_REELECTION:
			sem_post(g_pHaBaseMgr->ha_mutex);
			break;
			
		default:
			HA_LOG_DEBUG("Unrecognized msg nType %d ...\n", pConfMsg->nMsgType);
		}
	}

	HaSendConfigRespData(pConfMsg, nLength, pHaPktObj->nSequence, pHaHost);
	
	return 0;
}

/***callback hook when rcv configure response packet*/
int HaConfigRespCB(HaPktObject* pHaRespPktObj, HaHost* pHaHost)
{
	pthread_mutex_lock(&g_ConfigMutex);
	pthread_cond_signal(&g_ConfigCond);
	pthread_mutex_unlock(&g_ConfigMutex);
	
	return 0;
}

HaPacketHooks g_conf_hooks = 
{
	HA_PAYLOAD_CONFIGURE,
	"configure hooks",
	HaConfigReqCB,
	HaConfigRespCB,
	NULL,
	NULL,
	NULL
};

int ha_conf_init()
{
	if (ha_pkt_hooks_reg(&g_conf_hooks) < 0)
	{
		return -1;
	}
		
	mutex_init(&g_ConfigMutex);
	pthread_cond_init(&g_ConfigCond, NULL);
	
	return 0;
}