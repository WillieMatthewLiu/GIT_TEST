#ifndef __PARSER_RTSP_H__
#define __PARSER_RTSP_H__

/* Rtsp end tag length */
#define RTSP_END_TAG_LEN                4

/* Rtsp ip key string length */
#define RTSP_IP_KEY_STRING_LEN          7

/* Rtsp port key string */
#define RTSP_PORT_KEY_LEN               12

/* Rtsp session buff length */
#define RTSP_SESSION_BUFF_LEN           2048

/* Rtsp ip key string */
#define RTSP_IP_KEY_STRING              "rtsp://"

/* Rtsp server port key */
#define RTSP_CLIENT_PORT_KEY            "client_port="

/* Rtsp server port key */
#define RTSP_SERVER_PORT_KEY            "server_port="

/* Session connection status */
typedef enum RTSP_CONNECT_STATUS_E
{
	RTSP_DISCONNECT = 0,
	RTSP_CONNECTING,
	RTSP_CONNECTED
} RTSP_CONNECT_STATUS;

/* RTSP new routing information */
typedef struct RTSP_NEW_ROUTE_S
{
	struct server *data_svr;
	struct RTSP_NEW_ROUTE_S *next;
} RTSP_NEW_ROUTE;

/* RTSP session information */
typedef struct RTSP_SESSION_S
{
	int connecting;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
	RTSP_NEW_ROUTE *routes;
} RTSP_SESSION;

/* RTSP dynamic port occupancy information */
typedef struct RTSP_DYNAMIC_PORT_S
{
	int isUsed;
	struct server *svr;
} RTSP_DYNAMIC_PORT;

/* Session information */
typedef struct RTSP_DATA_SESSION_S
{
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} RTSP_DATA_SESSION;

void rtsp_writeSeceventLog(struct filter_header *hdr, int packLen, char *content, enum SVR_ID svrId);

#endif

