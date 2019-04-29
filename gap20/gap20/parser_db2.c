/* App Layer Parser for Oracle */
#include "app_common.h"
#include "parser_db2.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "nlkernel.h"
#include "parser_tcp.h"
#include "db_agent.h"

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

#define  DB2_HEAD_LEN 10
#define  DB2_MAGIC_OFFSET 2
#define  DB2_MAGIC ntohs(0xd0)

#define pntoh16(p)  ((uint16_t)                       \
	((uint16_t)*((const uint8_t *)(p)+0) << 8 | \
	(uint16_t)*((const uint8_t *)(p)+1) << 0))


enum DB2_STATE
{
	DB2_NONE,
	DB2_WAIT_HEAD,
	DB2_WAIT_DATA,
};

struct db2_session
{
	int connecting;
	struct evbuffer *parser_buf;
	struct evbuffer *send_buf;
	enum DB2_STATE state;
};

struct db2_session *db2_session_new()
{
	struct db2_session *session = SCMalloc(sizeof(struct db2_session));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	session->parser_buf = evbuffer_new();
	session->send_buf = evbuffer_new();
	session->connecting = FALSE;
	session->state = DB2_NONE;
	return session;
};

void db2_session_free(struct db2_session *session)
{
	evbuffer_free(session->send_buf);
	evbuffer_free(session->parser_buf);
	SCFree(session);
}

void db2_dumpbin(char *name, const uint8_t *buff, size_t len)

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

int db2_check_offset_length_no_exception(uint8_t * input, uint32_t input_len, const uint32_t offset, const uint32_t length_val, uint32_t * offset_ptr, uint32_t * length_ptr)
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

int db2_tvb_bytes_exist(uint8_t * input, const uint32_t input_len, const unsigned int offset, const unsigned int length)
{
	unsigned int abs_offset, abs_length;
	int exception;

	exception = db2_check_offset_length_no_exception(input, input_len, offset, length, &abs_offset, &abs_length);

	if (exception)
		return FALSE;

	return TRUE;
}

uint8_t * db2_fast_ensure_contiguous(uint8_t * input, const uint32_t input_len, const uint32_t offset, const uint32_t length)
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
		SCLogInfo("DB2: [ %s:%d ] out of bounds\n", __FILE__, __LINE__);

	return NULL;
}

uint8_t db2_tvb_get_uint8(uint8_t * input, const uint32_t input_len, const uint32_t offset)
{
	const uint8_t * ptr;
	ptr = db2_fast_ensure_contiguous(input, input_len, offset, sizeof(uint8_t));
	return *ptr;
}

uint16_t db2_tvb_get_ntohs(uint8_t * input, const uint32_t input_len, const uint32_t offset)
{
	uint8_t *ptr;
	uint16_t *pkt_len_ptr;
	uint16_t pkt_len;
	ptr = db2_fast_ensure_contiguous(input, input_len, offset, sizeof(uint16_t));
	pkt_len_ptr = (uint16_t*)ptr;
	pkt_len = ntohs(*pkt_len_ptr);
	return pkt_len;
}

enum FLT_RET db2_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	/* FLTEV_ONCLIIN */
	if (ev == FLTEV_ONCLIIN)
	{
		SCLogInfo("DB2: on cli in, ssid: %d", hdr->sessionid);
		struct db2_session *session = db2_session_new();
		if (session == NULL)
			return FLTRET_CLOSE;
		session->connecting = FALSE;
		hdr->user = session;
		return FLTRET_OK;
	}

	/* FLTEV_ONSVROK */
	else if (ev == FLTEV_ONSVROK)
	{
		struct db2_session *session = hdr->user;
		session->connecting = TRUE;
		int isok = *((int*)buff); assert(len == sizeof(isok));
		SCLogInfo("DB2: connect server ret: %d, ssid: %d", isok, hdr->sessionid);
		if (isok == 0)
			return db2_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		if (evbuffer_get_length(session->parser_buf) > 0)
			return db2_ondata(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		return FLTRET_OK;
	}

	/* FLTEV_ONSOCKDATA */
	else if (ev == FLTEV_ONSOCKDATA)
	{
		struct db2_session *session = hdr->user;
		uint8_t type_a = 0;
		int32_t offset = 0;
		uint16_t length = 0;
		char db2_head[80] = { 0 }; //the length of db2 head is 10 byte 
		char ip_src[20] = { 0 };
		char ip_dst[20] = { 0 };
		addr2str(hdr->ip->daddr, ip_dst);
		addr2str(hdr->ip->saddr, ip_src);

		SCLogInfo("DB2: on cli/svr len: %d, ssid: %d", (int)len, hdr->sessionid);
		//db2_dumpbin("on cli/svr data", buff, len);


		if (evbuffer_add(session->parser_buf, buff, len) != 0)
		{
			return db2_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		if (session->connecting == FALSE)
		{
			SCLogInfo("DB2: svr not ready, delay.... ssid: %d", hdr->sessionid);
			return FLTRET_OK;
		}


		while (1)
		{
			if (evbuffer_copyout(session->parser_buf, db2_head, DB2_HEAD_LEN) < DB2_HEAD_LEN || evbuffer_get_length(session->parser_buf) < DB2_HEAD_LEN)
			{
				break;
			}
			length = db2_tvb_get_ntohs((uint8_t *)db2_head, DB2_HEAD_LEN, offset);
			if (evbuffer_get_length(session->parser_buf) < length)
			{
				break;
			}

			type_a = db2_tvb_get_uint8((uint8_t *)db2_head, DB2_HEAD_LEN, DB2_MAGIC_OFFSET);
			if (type_a != DB2_MAGIC)
			{
				char *err = "No identify the package type";
				write_secevent_log(ip_src, ip_dst, hdr->username, "DB2", SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, "", PRI_HIGH, 0);
				return db2_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
			evbuffer_remove_buffer(session->parser_buf, session->send_buf, length);
		}

		if (evbuffer_sendtofwd(hdr, session->send_buf, 0) != 0)
		{
			char *err = "evbuffer_sendtofwd failed!!!";
			write_secevent_log(ip_src, ip_dst, hdr->username, "DB2", SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, "", PRI_HIGH, 0);
			return db2_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		hdr->timeout = 30 * 60;//30min
		return FLTRET_OK;
	}

	/* FLTEV_ONFWDDATA */
	else if (ev == FLTEV_ONFWDDATA)
	{
		const ForwardObject *obj = buff; assert(len == sizeof(obj));
		char ip_src[20] = { 0 };
		char ip_dst[20] = { 0 };
		addr2str(hdr->ip->daddr, ip_dst);
		addr2str(hdr->ip->saddr, ip_src);

		SCLogInfo("DB2: on fwd len:%d, ssid=%d", (int)obj->buffdata.len, hdr->sessionid);
		//db2_dumpbin("on fwd data", obj->buffdata.data, obj->buffdata.len);
		assert(obj->has_buffdata);
		int ret = buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len);
		if (ret != 0)
		{
			char *err = "buffer_sendtoreq failure";
			write_secevent_log(ip_src, ip_dst, hdr->username, "DB2", SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, "", PRI_HIGH, 0);
			return db2_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
		return FLTRET_OK;
	}

	/* FTLEV_ONSOCKERROR */
	else if (ev == FLTEV_ONSOCKERROR)
	{
		struct db2_session *session = hdr->user;
		SCLogInfo("DB2: on socket close, ssid: %d", hdr->sessionid);
		db2_session_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}
	else
	{
	}
	return FLTRET_OK;
}

int db2_oninit()
{
	return 0;
}

int db2_onfree()
{
	return 0;
}

static struct packet_filter g_filter_db2 = { SVR_ID_DB2, "db2 parser", db2_oninit, db2_ondata, db2_onfree };

PROTOCOL_FILTER_OP(db2)

