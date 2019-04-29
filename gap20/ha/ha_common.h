#ifndef _HAM_COMMON_H_
#define _HAM_COMMON_H_

#define RONGAN_HA_VERSION 1

typedef enum _HaPacketType
{
	HA_PACKET_REQ,						//����
	HA_PACKET_RESP,						//Ӧ��
}HaPacketType;

typedef enum _HaPaloadType
{
	HA_PAYLOAD_HEARTBEAT,				//��������
	HA_PAYLOAD_ELECTION,				//����ѡ������
	HA_PAYLOAD_CONFIGURE,				//��������
	HA_PAYLOAD_MAX
}HaPaloadType;

typedef struct  _HaPktObject
{
	uint32_t nVersion;					//�汾��
	uint32_t nAuthMode;					//HA��֤ģʽ
	uint32_t nReqRespType;				//���ݰ��������ͣ�0-����, 1-Ӧ�� HaPacketType
	uint32_t nPaLoadType;				//���ݰ��������� HaPaloadType
	uint32_t nSequence;					//���ݰ���� �Է��ͷ���seq�����������ģ���Ӧ���ĺ�����ͬ��seq*
	uint32_t nDataLen;					//�����峤�ȣ��������򣬲�������ͷ����
	uint8_t  chData[0];					//���ݿ�ʼ��ַ
}HaPktObject;

typedef struct _HaFaultNotifyMsg
{
	uint32_t	dwIPAddr;				//����֪ͨ���豸HA����IP��ַ
	int			nFaultState;			//����״̬
	int			nHaState;				//��Ҫ���õ�HA״̬ 
}HaFaultNotifyMsg;

/**HA election packet*/
struct ElectionPkt 
{
	uint8_t		nMyState;
	uint8_t		nMyPriority;
	uint16_t	nFlags;					// force to active if set 1, force to stanby if set 2
	HaFaultNotifyMsg rNotifyMsg;
};
typedef struct ElectionPkt HaElectionReq;
typedef struct ElectionPkt HaElectionResp;

/**	HA heartbeat packet*/
struct HeartBeatPkt 
{
	uint32_t	dwIPAddr;
	uint32_t	dwMyMask;	
	uint8_t		nInitState;
	uint8_t		nMyState;				// current state
	uint8_t		nMyPriority;		
};
typedef struct HeartBeatPkt HaHeartbeatReq;
typedef struct HeartBeatPkt HaHeartbeatResp;

typedef struct _HaPendingList 
{
	HashListTable* pHashTable;
	pthread_mutex_t ht_mutex;
}HaPendingList;

typedef struct _HaPendingObj 
{
	HaHost*			pHaHost;
	HaPktObject*	pHaPktObj;
	struct event*	pTimerEvent;	
}HaPendingObj;

typedef int(*OnReqCB)(HaPktObject* pHaPktObj, HaHost* pHaHost);
typedef int(*OnRespCB)(HaPktObject* pHaRespPktObj, HaHost* pHaHost);

typedef int(*OnLocalReqTimeoutCB)(HaPktObject* pHaPktObj, HaHost* pHaHost);
typedef uint32_t(*WaitTimeValueCB)();
typedef int(*SendtoErrCB)(HaHost* pHaHost);

typedef struct _HaPacketHooks
{
	HaPaloadType		nID;				//������������ID
	char*				pName;				//�ҹ�����
	OnReqCB				RequestCB;			//�������ݴ���ص�����
	OnRespCB			ResponseCB;			//Ӧ�����ݴ���ص�����
	OnLocalReqTimeoutCB LocalTimeoutCB;		//���ط����������ݳ�ʱ����ص�����
	WaitTimeValueCB		WaitTimeValCB;		//�����������ݳ�ʱʱ�����ú���
	SendtoErrCB			SendToErrCB;		//�������ݳ�����ص�����
}HaPacketHooks;

/************************ Function Define *******************/
uint8_t HaGetLocalState();
uint8_t HaGetLocalPriority();
uint32_t HaGetLocalIP();
uint32_t HaGetLocalMask();
uint16_t HaGetLocalPort();

int HaGetAuthMode();
uint8_t HaGetAutoFailback();

uint32_t HaGetHeartbeatIntervalTime();
uint32_t HaGetHeartbeatMaxwaitTime();

int ha_pkt_hooks_reg(HaPacketHooks* pPacketHooks);
void* HaLoopthread(void* pArg);
uint32_t HaGetPktSeqAndAdd();

int ha_response_hash_init();
int ha_init_bcast_sock(const char* pIfname);

int HaManagerSendData(HaPacketType nReqRespType, HaPaloadType nPaLoadType, uint32_t nSequence, uint8_t* pBuffer, int nLength, HaHost* pHaHost);

uint8_t HaGetLocalRunningState();

int HaStartRead(HaBaseMgr* pHaBaseMgr);

/** init conf module for send and recv configure msg*/
int ha_conf_init();

/**	init base mgr for ha pkt send & recv.*/
int ha_base_mgr_init();
void ha_base_mgr_deinit();

#endif