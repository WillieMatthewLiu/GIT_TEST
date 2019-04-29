#ifndef _HA_INOUT_H_
#define _HA_INOUT_H_

#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"
#include "ha_election.h"
#include "ha_appmgr.h"
#include "ha_agent.h"
#include "ha_statemgr.h"
#include "ha_conf.h"

#define INOUT_MAX_MESSAGE_LEN	(1024)
#define INOUT_DEV_SYNC_TIME		(3) //s

typedef enum _HaInoutMsgID
{
	HA_INOUT_STATE_SYNC,
	HA_INOUT_FAULT_NOTIFY,
	HA_INOUT_CONF_MSG,
}HaInoutMsgID;

typedef enum _HaInoutPacketType
{
	HA_INOUT_PACKET_REQ,
	HA_INOUT_PACKET_RESP,
	HA_INOUT_PACKET_NOTIFY,
}HaInoutPacketType;

typedef struct _HaInoutHostInfo
{
	uint8_t		nInitState;
	uint8_t		nRunningState;
	uint8_t		nPriority;
	 
	uint32_t	dwIPAddr;
	uint32_t	dwMask;

	time_t		nOnTime;
	time_t		nOffTime;
	int         nHostType;   	//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
	int         nConnectType; 	//0： 未知； 1：内外端连接  2：主备连接
}HaInoutHostInfo;

typedef struct _HaInoutSyncMsg
{
	uint8_t		nInitState;
	uint8_t		nRunningState;	
	uint8_t		nPriority;
	 
	uint32_t	dwIPAddr;
	uint32_t	dwMask;

	int			nHostCount;
	char		chData[0];
}HaInoutSyncMsg;

typedef struct _HaInoutPacket
{
	int		nType;			/* request/response/notify */
	int		nMsgID;
	union 
	{
		HaInoutSyncMsg		rSyncMsg;
		HaFaultNotifyMsg	rNotifyMsg;
		HaConfMsg			rConfigMsg;
		char				chData[INOUT_MAX_MESSAGE_LEN - 8];
	}u;
}HaInoutPacket;

typedef struct _HaInoutMgr
{
	int					nSocketFd;				/* data fd for inner and outter */
	int					nAcceptFd;				/* accept fd for outter */
	int					nSide;					/* 0: inner, 1: outter */
	uint32_t			dwLocalIP;				//本地IP地址
	int32_t			    dwPeerIP;				//对端IP地址
	int32_t				nLocalPort;				//本地端口
	uint16_t			nPeerPort;				//对端端口
	int					nTime;					//最近一次接收到数据的时间
	BOOL                bConnected;				//内外端是否已经连接成功
	BOOL                bHaveReSendData;		//是否有需要重发的数据包
	BOOL				bSwitchState;			//是否正在进行状态切换

	/* libevent member */
	struct event_base*	pInoutEventBase;
	struct event*		pBackgroudEvent;
	struct event*		pAcceptEvent;
	struct event*		pReadEvent;

	HaInoutPacket*		pRecvMsg;
	uint8_t				chDataBuffer[INOUT_MAX_MESSAGE_LEN];
}HaInoutMgr;

int partner_init_in(const char* pInSideIP, const char* pOutSideIP, uint16_t nPort);
int partner_init_out(const char* pInSideIP, uint16_t nPort);

int InoutSend(HaInoutPacket* pData, int nDataLen);

#endif