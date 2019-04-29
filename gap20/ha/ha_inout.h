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
	int         nHostType;   	//0�� δ֪�� 1���ڶ˻��� 2����˻�	 3: �Զ��ڶ˻� 4: �Զ���˻�
	int         nConnectType; 	//0�� δ֪�� 1�����������  2����������
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
	uint32_t			dwLocalIP;				//����IP��ַ
	int32_t			    dwPeerIP;				//�Զ�IP��ַ
	int32_t				nLocalPort;				//���ض˿�
	uint16_t			nPeerPort;				//�Զ˶˿�
	int					nTime;					//���һ�ν��յ����ݵ�ʱ��
	BOOL                bConnected;				//������Ƿ��Ѿ����ӳɹ�
	BOOL                bHaveReSendData;		//�Ƿ�����Ҫ�ط������ݰ�
	BOOL				bSwitchState;			//�Ƿ����ڽ���״̬�л�

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