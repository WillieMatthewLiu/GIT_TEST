#ifndef _HA_H_
#define _HA_H_

#include "util-list.h"
#include "util-debug.h"

#ifndef ENABLE
#define ENABLE 1
#endif

#ifndef DISABLE
#define DISABLE 0
#endif

typedef unsigned int		DWORD;
typedef int					BOOL;
typedef unsigned char		BYTE;
typedef unsigned short		WORD;
typedef float               FLOAT;
typedef FLOAT               *PFLOAT;

typedef BYTE                *LPBYTE;

typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int        *PUINT;

typedef unsigned long		ULONG;
typedef unsigned long		*PULONG;

#define HA_SHM_SEMPHERE_NAM				"ha.sem"

#define HA_LOG_DEBUG(...)				SCLogInfo(__VA_ARGS__)
#define HA_LOG_WARNING(...)				SCLogWarning(__VA_ARGS__)
#define HA_LOG_ERROR(...)				SCLogError(__VA_ARGS__)
#define HA_APP_MGR_PATH					"/var/run/ha.app.mgr"

/**	HA error code enum.*/
typedef enum _HaErrorCode
{
	HA_SUCCESS = 0,						//success
	HA_ERROR_ERROR,						//common error
	HA_ERROR_NOMEM,						//no memory
	HA_ERROR_EXIST,						//entiry exist
	HA_ERROR_NOEXIST,					//entiry no exist
	HA_ERROR_READ,						//read error
	HA_ERROR_WRITE,						//write error
	HA_ERROR_TIMEOUT,					//timeout
	HA_ERROR_PARAM						//param error
} HaErrorCode;

/**	HA event enum*/	
typedef enum _HAEvent 
{
	HA_EVENT_START = 0,

	/* HA state change event */
	HA_EVENT_GO_OOS_NORMAL,				//通知应用模块进入OOS状态，指示即将发生平滑切换等。应用模块完成相关处理（比如数据同步）后，必须向HaAppMgr回HA_APP_EVENT_OOS事件。
	HA_EVENT_GO_OOS_FORCED,				//通知应用模块进入OOS状态，指示即将发生强制切换。应用模块完成相关处理（比如关键数据同步）后，必须向HaAppMgr回HA_APP_EVENT_OOS事件。
	HA_EVENT_GO_OOS,					//通知应用模块进入OOS状态
	HA_EVENT_GO_ACT,					//通知应用模块进入Active状态。应用模块完成相关处理后，必须向HaAppMgr回HA_APP_EVENT_ACT事件。
	HA_EVENT_GO_STB,					//通知应用模块进入Standby状态。应用模块完成相关处理后，必须向HaAppMgr回HA_APP_EVENT_STB事件。

	/* HA Standby event */
	HA_EVENT_STB_UP,					//通知应用模块备机上线（主机侧事件）
	HA_EVENT_STB_DOWN,					//通知应用模块备机离线（主机侧事件）
	HA_EVENT_PEER_CONN_OK,				//通知应用同步通道建立成功，可以开始快速同步。应用模块完成快速同步后，需要响应HA_APP_EVENT_FAST_SYNC_FINISH。		
										//if a new STB up, the data sync channel will connect to this STB, if connect OK, start data sync 
	HA_EVENT_PEER_CONN_FAIL,			//通知应用模块停止同步。
	HA_EVENT_SYNC_CONGESTION_L,			//通知应用模块减慢同步数据
	HA_EVENT_SYNC_CONGESTION_H,			//通知应用模块暂停同步数据。

	/* heartbeat event*/
	HA_EVENT_HB_ON,						//心跳检测正常
	HA_EVENT_HB_LOSS,					//心跳检测模块检测到心跳不正常
	HA_EVENT_HB_LOSS_EXTERN,			//外部模块如内外端机模块检测到心跳不正常

	/* ha set configuration event */
	HA_EVENT_CONF_STOP_TIMER,			//stop timer
	HA_EVENT_CONF_CLOSE_SOCKET,			//close socket
	HA_EVENT_CONF_RECOVER,				//recover ha

	/* HA APP event */
	HA_EVENT_APP_REGISTER,				//应用模块注册
	HA_APP_EVENT_ACT,					//应用模块已经进入Active状态
	HA_APP_EVENT_STB,					//应用模块已经进入Standby状态
	HA_APP_EVENT_OOS,					//应用模块已经进入Standby状态
	HA_EVENT_DATA,						//when ACT start data sync, STB will cause this event 
	HA_APP_EVENT_FAST_SYNC_FINISH,		//应用模块完成快速同步。
	HA_APP_EVENT_SYNC_FAIL,				//应用模块同步失败。HaAppMgr应该在之后，控制应用模块重新做快速同步
	HA_EVENT_MAX
}HAEvent;

/**	HA and Application message type.*/
typedef enum _HaAppMsgID 
{
	HA_APP_REGISTER,					//注册
	HA_APP_UNREGISTER,					//注销
	HA_APP_EVENT_NOTIFY,				//HA detect status change, send this
	HA_APP_DATA_SYNC,					//数据同步
}HaAppMsgID;

/**	HA auth mode*/
enum 
{
	HA_AUTH_NONE,
	HA_AUTH_CHECKSUM,
	HA_AUTH_MD5,
	HA_AUTH_SHA,
	HA_AUTH_MAX
};

/**HA APP callback function define.*/
typedef int(*ha_event_cb)(HAEvent nHaEvent, void* pParam);
typedef void(*ha_sync_recv_cb)(uint32_t dwAppModID, const char* pData, uint32_t nDataLen);

typedef enum _HaState 
{
	HA_STATE_INIT,
	HA_STATE_OOS,
	HA_STATE_STB,
	HA_STATE_ACT,
}HaState;

#define HA_APP_MESSAGE_LEN_MAX 8192

//应用程序与HA之间的消息结构采用TLV格式
typedef struct _HaAppMessageHead 
{
	int			nType;							//消息类型：request/response/trap 
	int			nAppMsgID;						//消息命令ID，HaAppMsgID枚举值
	uint32_t	dwAppModID;						//应用程序ID
	int			nTotalLen;						//数据包部长度，包含数据头长度和数据休长度
}HaAppMessageHead;

#define HA_APP_MESSAGE_HEAD_LEN (sizeof(HaAppMessageHead))

typedef struct _HaEventMsg 
{
	HAEvent		nHaEvent;
	char		chData[0];
}HaEventMsg;

typedef struct _HaAppMessage
{
	HaAppMessageHead rAppMessageHead;
	union 
	{
		HaErrorCode nReturn;
		HaEventMsg  rEventMsg;
		char		chData[HA_APP_MESSAGE_LEN_MAX];
	}u;
}HaAppMessage;

//get error code string.
static inline const char* ha_error_to_str(int ec) 
{
	switch (ec) 
	{
	case HA_SUCCESS:
		return "success";
		
	case HA_ERROR_ERROR:
	case -HA_ERROR_ERROR:
		return "common error";
		
	case HA_ERROR_NOMEM:
	case -HA_ERROR_NOMEM:
		return "no memory";
		
	case HA_ERROR_EXIST:
	case -HA_ERROR_EXIST:
		return "entiry exist";
		
	case HA_ERROR_NOEXIST:
	case -HA_ERROR_NOEXIST:
		return "entiry no exist";
		
	case HA_ERROR_READ:
	case -HA_ERROR_READ:
		return "read error";
		
	case HA_ERROR_WRITE:
	case -HA_ERROR_WRITE:
		return "write error";
		
	case HA_ERROR_TIMEOUT:
	case -HA_ERROR_TIMEOUT:
		return "timeout";
		
	case HA_ERROR_PARAM:
	case -HA_ERROR_PARAM:
		return "param error";
		
	default:
		return "unkown";
	}
}

//get state string
static inline const char* ha_state_to_str(HaState s)
{
	switch (s)
	{
	case HA_STATE_INIT:
		return "init";
		
	case HA_STATE_OOS:
		return "OOS";
		
	case HA_STATE_STB:
		return "STB";
		
	case HA_STATE_ACT:
		return "ACT";

	default:
		return "unkown.";
	}
}

//get event string
static inline const char* ha_event_to_str(HAEvent e)
{
	switch (e)
	{
	case HA_EVENT_GO_OOS:
		return "go OOS";
		
	case HA_EVENT_GO_ACT:
		return "go ACT";
		
	case HA_EVENT_GO_STB:
		return "go STB";
		
	case HA_EVENT_STB_UP:
		return "STB UP";
		
	case HA_EVENT_STB_DOWN:
		return "STB down";
		
	case HA_EVENT_PEER_CONN_OK:
		return "peer conn ok";
		
	case HA_EVENT_PEER_CONN_FAIL:
		return "peer conn error";
		
	case HA_EVENT_SYNC_CONGESTION_L:
		return "sync congestion slow";
		
	case HA_EVENT_SYNC_CONGESTION_H:
		return "sync congestion fast";
		
	case HA_EVENT_HB_ON:
		return "HB on";
		
	case HA_EVENT_HB_LOSS:
		return "HB loss";
		
	case HA_EVENT_CONF_STOP_TIMER:
		return "stop timer";
		
	case HA_EVENT_CONF_CLOSE_SOCKET:
		return "close socket";
		
	case HA_EVENT_CONF_RECOVER:
		return "recover ha";
		
	case HA_EVENT_APP_REGISTER:
		return "app register";
		
	case HA_APP_EVENT_ACT:
		return "app in act";
		
	case HA_APP_EVENT_STB:
		return "app in stb";
		
	case HA_APP_EVENT_OOS:
		return "app in oos";
		
	case HA_EVENT_DATA:
	case HA_APP_EVENT_FAST_SYNC_FINISH:
	case HA_APP_EVENT_SYNC_FAIL:
	default:
		return "unkown event.";
	}
}

//get pkt type string
static inline const char* ha_pkt_type(uint8_t x)
{
	switch (x)
	{
	case 0:
		return "request";
		
	case 1:
		return "response";
		
	default:
		return "unkown type";
	}
}

//get payload string
static inline const char* ha_payload_type(uint8_t x)
{
	switch (x)
	{
	case 0:
		return "heartbeat";
		
	case 1:
		return "election";
		
	default:
		return "unkown type";
	}
}

/**	APP register to HA.
	@param dwAppModID to indicate which Application will use HA function.
	@param nFlags bit0 to indicate this Application is last.
	@param pNotifCBF a event callback function to process
	@param pSyncRcvCBF a data sync function to process
	@param pParam customize parameters.
	@retrun HA error code.*/
HaErrorCode ha_app_register(uint32_t dwAppModID,
	uint32_t nFlags,
	ha_event_cb pNotifCBF,
	ha_sync_recv_cb pSyncRcvCBF,
	void* pParam);

/**APP unregister from HA
	@param dwAppModID to indicate which Application will use HA function.
	@retrun HA error code.*/
HaErrorCode ha_app_unregister(uint32_t dwAppModID);

/**	when last Application finish register, call this function to notify HA to work.
	@retrun void.*/
void ha_app_register_finish_notify();

/**	ha data sync, when STB up, ACT can call this function to sync data to STB.
	@param dwAppModID Application or Module ID
	@param data sync data
	@param len data length
	@return HA Error code*/
int ha_data_sync(uint32_t dwAppModID, const char* pData, int nDataLen);

#endif