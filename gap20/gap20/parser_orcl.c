/* App Layer Parser for Oracle */
#include "app_common.h"
#include "parser_orcl.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "nlkernel.h"
#include "parser_tcp.h"
#include "db_agent.h"
#include "parser_common.h"
#include "db_mysql.h"
#include "gap_cmd_group.h"

/* Packet Types */
#define TNS_TYPE_CONNECT 1
#define TNS_TYPE_ACCEPT 2
#define TNS_TYPE_ACK 3
#define TNS_TYPE_REFUSE 4
#define TNS_TYPE_REDIRECT 5
#define TNS_TYPE_DATA 6
#define TNS_TYPE_NULL 7
#define TNS_TYPE_ABORT 9
#define TNS_TYPE_RESEND 11
#define TNS_TYPE_MARKER 12
#define TNS_TYPE_ATTENTION 13
#define TNS_TYPE_CONTROL 14
#define TNS_TYPE_MAX 19

#define TRUE 1
#define FALSE 0
#define OFFSET_ERROR -1
#define BoundsError	 2
#define OutLengthError 3

#define pntoh16(p)  ((uint16_t)                       \
                     ((uint16_t)*((const uint8_t *)(p)+0)<<8|  \
                      (uint16_t)*((const uint8_t *)(p)+1)<<0))


static FLT_ONPKTCB g_orcl_ondata_cb[FLTEV_COUNT] = { 0 };
static enum FLT_RET orcl_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET orcl_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET orcl_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET orcl_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET orcl_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);

enum ORCL_STATE
{
	ORCL_NONE,
	ORCL_WAIT_HEAD,
	ORCL_WAIT_DATA,
};

struct orcl_session
{
	struct evbuffer *buf;
	enum ORCL_STATE state;
};

struct orcl_session *orcl_session_new()
{
	struct orcl_session *session = SCMalloc(sizeof(struct orcl_session));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	session->buf = evbuffer_new();
	session->state = ORCL_NONE;
	return session;
};

void orcl_session_free(struct orcl_session *session)
{
	evbuffer_free(session->buf);
	SCFree(session);
}

void dumpbin(char *name, const uint8_t *buff, size_t len)
{
	printf("%s(%d):\n", name, (int)len);
	for (int i = 0; i < len; i++)
	{
		printf("%02X ", buff[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

int check_offset_length_no_exception(uint8_t * input, uint32_t input_len, const uint32_t offset, const uint32_t length_val, uint32_t * offset_ptr, uint32_t * length_ptr)
{
	uint32_t end_offset;
	if (offset <= input_len)
		*offset_ptr = offset;

	*length_ptr = length_val;
	end_offset = *offset_ptr + *length_ptr;

	if (end_offset <= input_len)
		return 0;
	else
		return BoundsError;
}

int tvb_bytes_exist(uint8_t * input, const uint32_t input_len, const unsigned int offset, const unsigned int length)
{
	unsigned int abs_offset, abs_length;
	int exception;

	exception = check_offset_length_no_exception(input, input_len, offset, length, &abs_offset, &abs_length);

	if (exception)
		return FALSE;

	return TRUE;
}

uint8_t * fast_ensure_contiguous(uint8_t * input, const uint32_t input_len, const uint32_t offset, const uint32_t length)
{
	uint32_t end_offset;
	uint32_t u_offset;

	if (!input)
		return NULL;

	u_offset = offset;
	end_offset = u_offset + length;

	if (end_offset <= input_len)
	{
		return input + u_offset;
	}

	if (end_offset > input_len)
		SCLogInfo("[ %s:%d ] out of bounds\n", __FILE__, __LINE__);

	return NULL;
}

uint8_t tvb_get_uint8(uint8_t * input, const uint32_t input_len, const uint32_t offset)
{
	const uint8_t * ptr;
	ptr = fast_ensure_contiguous(input, input_len, offset, sizeof(uint8_t));
	return *ptr;
}

uint16_t tvb_get_ntohs(uint8_t * input, const uint32_t input_len, const uint32_t offset)
{
	uint8_t *ptr;
	uint16_t *pkt_len_ptr;
	uint16_t pkt_len;
	ptr = fast_ensure_contiguous(input, input_len, offset, sizeof(uint16_t));
	pkt_len_ptr = (uint16_t*)ptr;
	pkt_len = ntohs(*pkt_len_ptr);
	return pkt_len;
}

static void orcl_write_secauditlog(struct filter_header *hdr, int level, char *rule, char *content)
{
	char sip[20];
	char dip[20];
	char *user = NULL;
	char *proto = NULL;
	uint32_t *autoId = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	user = hdr->username ? hdr->username : "none";
	proto = (char*)server_strfromid(SVR_ID_ORCL);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, hdr->tcp->source, hdr->tcp->dest, proto,
		user, "none", level, rule, "权限被拒绝", strlen(content), content);
}

enum FLT_RET orcl_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SCLogInfo("ORCL: on cli in, ssid: %d", hdr->sessionid);
	struct orcl_session *session = orcl_session_new();
	if (session == NULL)
		return FLTRET_CLOSE;
	hdr->user = session;
	return FLTRET_OK;
}

enum FLT_RET orcl_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	int isok = *((int*)buff); assert(len == sizeof(isok));
	SCLogInfo("ORCL: connect server ret: %d, ssid: %d", isok, hdr->sessionid);
	if (isok == 0)
		return orcl_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	return FLTRET_OK;
}

enum FLT_RET orcl_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct orcl_session *session = hdr->user;
	uint8_t type_a = 0;
	int32_t offset = 0;
	uint16_t length = 0;
	char orcl_head[64] = { 0 };
	SCLogInfo("ORCL: on cli/svr len: %d, ssid: %d", (int)len, hdr->sessionid);

	if (evbuffer_add(session->buf, buff, len) != 0)
		return orcl_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);

	if (evbuffer_get_length(session->buf) < 8)
		return FLTRET_OK;

	if (evbuffer_copyout(session->buf, orcl_head, 8) != 8)
		return orcl_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);

	type_a = tvb_get_uint8((uint8_t *)orcl_head, 8, 4);
	if (type_a < TNS_TYPE_CONNECT || type_a > TNS_TYPE_MAX)
	{
		orcl_write_secauditlog(hdr, l_critical, "packet type", "非法的数据包类型");
	}

	length = tvb_get_ntohs((uint8_t *)orcl_head, 8, offset);

	if (evbuffer_get_length(session->buf) < length)
		return FLTRET_OK;

	if (evbuffer_sendtofwd(hdr, session->buf, length) != 0)
	{
		return orcl_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	if (evbuffer_get_length(session->buf) > 0)
	{
		SCLogInfo("ORCL: session->buf has extra data len:%d\n", evbuffer_get_length(session->buf));
		return orcl_onsockdata(hdr, FLTEV_ONSOCKDATA, NULL, 0);
	}

	return FLTRET_OK;
}

enum FLT_RET orcl_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	const ForwardObject *obj = buff; assert(len == sizeof(obj));
	SCLogInfo("ORCL: on fwd len:%d, ssid=%d", (int)obj->buffdata.len, hdr->sessionid);

	if (obj->cmd == FWDCMD_FORWARDDATA)
	{
		assert(obj->has_buffdata);
		int ret = buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len);
		if (ret != 0)
		{
			return orcl_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
	}

	return FLTRET_OK;
}

enum FLT_RET orcl_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct orcl_session *session = hdr->user;
	SCLogInfo("ORCL: on socket close, ssid: %d", hdr->sessionid);
	orcl_session_free(session);
	hdr->user = NULL;
	return FLTRET_CLOSE;
}

enum FLT_RET orcl_oninit()
{
	g_orcl_ondata_cb[FLTEV_ONCLIIN] = orcl_oncliin;
	g_orcl_ondata_cb[FLTEV_ONSVROK] = orcl_svrok;
	g_orcl_ondata_cb[FLTEV_ONSOCKDATA] = orcl_onsockdata;
	g_orcl_ondata_cb[FLTEV_ONFWDDATA] = orcl_onfwddata;
	g_orcl_ondata_cb[FLTEV_ONSOCKERROR] = orcl_onsockerr;
	return FLTRET_OK;
}

enum FLT_RET orcl_onpkt(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	return g_orcl_ondata_cb[ev](hdr, ev, buff, len);
}

enum FLT_RET orcl_onfree()
{
	return FLTRET_OK;
}

enum SVR_ID orcl_check_data(const void *buff, size_t len)
{
	if (len > 8 && memcmp(buff + 2, "\x00\x00\x01\x00\x00\x00", 6) == 0)
		return SVR_ID_ORCL;
	return _SVR_ID_NONE;
}

static struct packet_filter g_filter_orcl = { SVR_ID_ORCL, "orcl parser", orcl_oninit, orcl_onpkt, orcl_onfree, orcl_check_data };

PROTOCOL_FILTER_OP(orcl)