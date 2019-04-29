#ifndef _HAM_COMMON_H_
#define _HAM_COMMON_H_

#define RONGAN_HA_VERSION 1

typedef enum _HaPacketType
{
	HA_PACKET_REQ,						//请求
	HA_PACKET_RESP,						//应答
}HaPacketType;

typedef enum _HaPaloadType
{
	HA_PAYLOAD_HEARTBEAT,				//心跳数据
	HA_PAYLOAD_ELECTION,				//主备选举数据
	HA_PAYLOAD_CONFIGURE,				//配置数据
	HA_PAYLOAD_MAX
}HaPaloadType;

typedef struct  _HaPktObject
{
	uint32_t nVersion;					//版本号
	uint32_t nAuthMode;					//HA认证模式
	uint32_t nReqRespType;				//数据包命令类型，0-请求, 1-应答 HaPacketType
	uint32_t nPaLoadType;				//数据包内容类型 HaPaloadType
	uint32_t nSequence;					//数据包序号 对发送方，seq是连续增长的，响应报文含有相同的seq*
	uint32_t nDataLen;					//数据体长度，数据区域，不含数据头部分
	uint8_t  chData[0];					//数据开始地址
}HaPktObject;

typedef struct _HaFaultNotifyMsg
{
	uint32_t	dwIPAddr;				//发起通知的设备HA网口IP地址
	int			nFaultState;			//故障状态
	int			nHaState;				//将要设置的HA状态 
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
	HaPaloadType		nID;				//处理数据类型ID
	char*				pName;				//挂钩名称
	OnReqCB				RequestCB;			//请求数据处理回调函数
	OnRespCB			ResponseCB;			//应答数据处理回调函数
	OnLocalReqTimeoutCB LocalTimeoutCB;		//本地发送请求数据超时处理回调函数
	WaitTimeValueCB		WaitTimeValCB;		//发送请求数据超时时间设置函数
	SendtoErrCB			SendToErrCB;		//发送数据出错处理回调函数
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