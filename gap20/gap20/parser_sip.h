#ifndef __PARSER_SIP_H__
#define __PARSER_SIP_H__

/* Content length max bits */
#define SIP_CONTENT_LEN_MAX_BITS    5

/* Status code length */
#define SIP_STATUS_CODE_LEN         3

/* Cseq buff length */
#define SIP_CSEQ_BUFF_LEN           16

/* Tag length */
#define SIP_TAG_BUFF_LEN            16

/* IP address cache size */
#define SIP_IP_BUFF_SIZE            64
#define SIP_PORT_BUFF_SIZE          6

/* SIP application cache size */
#define SIP_BUFF_DATA_LEN           1536

/* Data processing rule */
typedef enum SIP_DATA_RULE_E
{
	SIP_DATA_NORMAL = 0,
	SIP_DATA_DROP,
	SIP_DATA_CLOSE
} SIP_DATA_RULE;

/* Session subjects of header */
typedef enum SIP_HEADER_SUBJECT_ID_E
{
	SIP_VIA = 0,
	SIP_MAX_FORWARDS,
	SIP_CONTACT,
	SIP_TO,
	SIP_FROM,
	SIP_CALL_ID,
	SIP_CSEQ,
	SIP_CONTENT_LENGTH,
	SIP_WWW_AUTHENTICATE,
	SIP_PROXY_AUTHORIZATION,
	SIP_AUTHORIZATION,
	SIP_RECORD_ROUTE,
	SIP_ROUTE,
	SIP_HEADER_SUBJECT_ID_BUTT
} SIP_HEADER_SUBJECT_ID;

/* Session subjects of body */
typedef enum SIP_BODY_SUBJECT_ID_E
{
	SIP_OWNER = 0,
	SIP_CONNECTION,
	SIP_MEDIA_AUDIO,
	SIP_MEDIA_VIDEO,
	SIP_MEDIA_ALT,
	SIP_BODY_SUBJECT_ID_BUTT
} SIP_BODY_SUBJECT_ID;

/* Method */
typedef enum SIP_METHOD_ID_E
{
	SIP_SIP = 0,
	SIP_REGISTER,
	SIP_SUBSCRIBE,
	SIP_INVITE,
	SIP_ACK,
	SIP_CANCEL,
	SIP_BYE,
	SIP_OPTIONS,
	SIP_INFO,
	SIP_PRACK,
	SIP_REFER,
	SIP_NOTIFY,
	SIP_UPDATE,
	SIP_MESSAGE,
	SIP_METHOD_BUTT
} SIP_METHOD_ID;

/* Status */
typedef enum SIP_STATUS_ID_E
{
	SIP_1XX = 1,
	SIP_2XX,
	SIP_3XX,
	SIP_4XX,
	SIP_5XX,
	SIP_6XX,
	SIP_STATUS_BUTT
} SIP_STATUS_ID;

/* SIP new routing information */
typedef struct SIP_NEW_ROUTE_S
{
	int inUsed;
	unsigned short newPortMsg;
	unsigned short newPortReport;
	struct server *data_svr;
	struct SIP_NEW_ROUTE_S *next;
	char fromTag[SIP_TAG_BUFF_LEN];
} SIP_NEW_ROUTE;

/* Session information */
typedef struct SIP_SESSION_S
{
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
	SIP_NEW_ROUTE *routes;
} SIP_SESSION;

/* Lunch information */
typedef struct SIP_LUNCH_S
{
	int len;
	char *name;
} SIP_LUNCH;

/* SIP dynamic port occupancy information */
typedef struct SIP_DYNAMIC_PORT_S
{
	int isUsed;
	struct server *svr;
} SIP_DYNAMIC_PORT;

/* Session information */
typedef struct SIP_DATA_SESSION_S
{
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} SIP_DATA_SESSION;

void sip_writeSeceventLog(struct filter_header *hdr, int packLen, char *content, enum SVR_ID svrId);

#endif

