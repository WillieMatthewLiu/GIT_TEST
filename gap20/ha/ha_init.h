#ifndef _HA_INIT_H_
#define _HA_INIT_H_

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#define LIBEVENT_DEFAULT_TIMER		1
#define HA_CONF_CMD_LEN				256
#define HA_ALLOWED_PORT_HASH_SIZE	1
#define HA_DEFAULT_MASK				0x00ffffff

/* default udp listen port */
#define HA_DEFAULT_PORT				8341

typedef enum _HaMachineRole
{
	HA_LOCAL_INNER,
	HA_LOCAL_OUTER,
	HA_PEER_INNER,
	HA_PEER_OUTER,
	HA_MACHINE_MAX
}HaMachineRole;

typedef enum _HaCmdErrCode
{
	HA_CMD_SUCCESS = 100,
	HA_CMD_IP_SEGMENT_ERR,
	HA_CMD_IP_ACT_STB_SAME_ERR,
	HA_CMD_CONFIG_STB_OUTER_ERR,
	HA_CMD_CONFIG_STB_INNER_ERR,
	HA_CMD_CONFIG_ACT_OUTER_ERR,
	HA_CMD_CONFIG_ACT_INNER_ERR,
	HA_CMD_OTHER_ERR,
}HaCmdErrCode;

/************************ Stuct Define ***********************/

struct HaInitFun 
{
	int(*init)();
	void(*deinit)();
};

/**	stuct define for ha global configuration.*/
#define HA_MAX_INTF_NAME_LEN 32

typedef struct _HaSysConfig
{
	char chIntface[HA_MAX_INTF_NAME_LEN];	/* ha run interface name, default is eth0 */
	struct in_addr	rLocalIPAddr;			/* HA running ip */
	uint32_t		dwLocalMask;			/* HA net mask */
	uint16_t		nLocalPort;				/* lcoal port */
	
	uint8_t			nPriority;				/* election priority */
	uint8_t			nInitState;				/* init state, ACT or STB */
	uint8_t			nAutoFailBack;			/*  */
	uint8_t			nAuthMode;				/* HA packet authentication mode
											  0 - No auth
											  1 - Checksum
											  2 - MD5
											  3 - SHA*/
	uint32_t		nIntervalTime;			/* heartbeat interval time, ms */
	uint32_t		nWaitTime;				/* heartbeat max wait time, ms */

	struct timeval  rGarpRefreshTimer;		/* Next scheduled gratuitous ARP timer */
	int				nGarpRepeat;			/* gratuitous ARP repeat value */
	int				nGarpRefreshRepeat;		/* refresh gratuitous ARP repeat value */
}HaSysConfig;

typedef struct _HaHost
{
	HaState				nInitState;
	HaState				nRunningState;	
	uint8_t				nPriority;
	struct sockaddr_in	rAddr;
	uint32_t			dwMask;

	time_t				nOnTime;
	time_t				nOffTime;

	int                 nHostType;  	//0： 未知； 1：内端机； 2：外端机	 3: 对端内端机 4: 对端外端机
	int                 nConnectType;	//0： 未知； 1：内外端连接  2：主备连接

	/* for sync channel, when run as ACT, will connect to STB by TCP */
	int					nSyncFd;
	struct evbuffer*	pRecvBuffer;
	struct bufferevent* pBufferEvent;	
}HaHost;

typedef struct _HaBaseMgr
{
	int					nUdpSockFd;				/* udp socket for election and heartbeat */
	sem_t*				ha_mutex;				/* election sem */
	
	int					nTime; 					//最近一次接收到数据的时间
	BOOL                bStopTimer;				//是否停止定时器超时检测

	BOOL                bConnected;				//主备端是否已经连接成功，有数据通信

	/* pkt send sequnce */
	pthread_mutex_t		seq_lock;
	uint32_t			nPacketSeq;

	/* event member */
	struct event_base*	pHaEventBase;
	struct event*		pBackgroudEvent;
	struct event*		pRecvEvent;
	pthread_t			evthread;

	/* HA status member */
	pthread_mutex_t		state_lock;
	HaState				nHaState;

	/* HA host list member*/
	HaHost				rHaHostArray[4];			//0：本地内端机 1：本地外端机 2：对方设备内端机 3：对方设备外端机

	/* heartbeat member*/
	struct event*		HbSendReqTimer;				/* send heartbeat request packet periodically */
}HaBaseMgr;

typedef struct _HaConfigureCmds
{
	HaMachineRole	nMachineRole;
	int				nMachineExist;
	HaState			nInitState;
	HaState			nRunningState;
	uint32_t		nPriority;
	uint32_t		dwIP;							//net order
	uint32_t		dwMask;							//net order
	uint16_t		nPort;
	char			chCmds[HA_CONF_CMD_LEN];
}HaConfigureCmds;

extern int g_nBoardType;
extern HaHost g_rBcastHost;
extern HaBaseMgr* g_pHaBaseMgr;

/************************ Function Define *******************/
char* HaGetInterfaceName();

/**	start Ha process, send elections, response heartbeat.*/
int StartHa();

/**HA command line init.*/
void ha_cmd_init();
HaErrorCode HaInit();
void HaDeinit();

HaSysConfig* HaGetConfig();

HaErrorCode HaSetInterface(const char* pIfname);
int HaSetIPPort(const char* pIP, const char* pMask, uint16_t nPort);

void HaSetPriority(uint32_t nPriority);
void HaSetInitState(HaState nHaState);

void HaAutoFailbackEnable();
void HaAutoFailbackDisable();
void HaSetHeartbeatTime(uint32_t nIntervalTime, uint32_t nWaitTime);

int HaSysConfigInit();

int ha_sync_mgr_init();
void ha_sync_mgr_deinit();

int HaSendDataToStb(const char* pData, int nDataLen);
char* HaStrTime(time_t* pTime);
 
int ha_conf_cmds_mem_init();
void ha_conf_cmds_mem_deinit();
void HaIptInit();
int ipm_init();

BOOL CheckBusinessInif();

int InoutSyncElectionRestart(int nHaState);
void ReInitUdpSocket();

#endif