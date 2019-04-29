
#include "app_common.h"
#include "parser_tcp.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"

//////////////////////////////////////////////////////////////////////////
// predef
static FLT_ONPKTCB g_tcp_ondata_cb[FLTEV_COUNT] = { 0 };
static enum FLT_RET tcp_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET tcp_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET tcp_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET tcp_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET tcp_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);


//////////////////////////////////////////////////////////////////////////
// session functions
struct tcp_session
{
	int connectok;
	struct evbuffer *buf;
};

static struct tcp_session* tcp_session_new()
{
	struct tcp_session *session = SCMalloc(sizeof(struct tcp_session));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	session->buf = evbuffer_new();
	session->connectok = 0;
	return session;
}

static void tcp_session_free(struct tcp_session *session)
{
	if (session != NULL)
	{
		evbuffer_free(session->buf);
		SCFree(session);
	}	
}


//////////////////////////////////////////////////////////////////////////
// helper functions
int buffer_sendtofwd(struct filter_header *hdr, const void *buff, size_t length)
{
	tlvbox_put_bytes(hdr->tlv_out, TLV_COMM_BUFFDATA, buff, length);
	return 0;
}

int evbuffer_sendtofwd(struct filter_header *hdr, struct evbuffer *evbf, size_t length)
{
	if (length == 0)
		length = evbuffer_get_length(evbf);
	tlvbox_put_bytes_evbf(hdr->tlv_out, TLV_COMM_BUFFDATA, evbf, length);
	return 0;
}

int buffer_sendtoreq(struct filter_header *hdr, const void *buff, size_t len)
{
	return hdr->reqcb(hdr, buff, len);
}
int evbuffer_sendtoreq(struct filter_header *hdr, struct evbuffer *evbf, size_t length)
{
	if (evbuffer_get_length(evbf) == 0)
		return 0;
	if (length == 0)
		length = evbuffer_get_length(evbf);
	if (evbuffer_get_length(evbf) < length)
		return -1;

	char buff[10240];
	while (length > 0)
	{
		size_t cnt = (length > sizeof(buff)) ? sizeof(buff) : length;
		evbuffer_remove(evbf, buff, cnt);

		int ret = hdr->reqcb(hdr, buff, cnt);
		if (ret != 0)
		{
			evbuffer_drain(evbf, length);
			return -1;
		}

		length -= cnt;
	}
	return 0;
}



//////////////////////////////////////////////////////////////////////////
// parser functions
static enum FLT_RET tcp_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct tcp_session *session = tcp_session_new();
	if (session == NULL)
		return FLTRET_CLOSE;
	hdr->user = session;
	SCLogInfo("TCP: on cli in, ssid: %d", hdr->sessionid);
	return FLTRET_OK;
}

static enum FLT_RET tcp_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct tcp_session *session = hdr->user;

	int isok = *((int*)buff); assert(len == sizeof(isok));
	SCLogInfo("TCP: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

	if (isok == 0)
		return tcp_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);

	session->connectok = 1;
	if (evbuffer_get_length(session->buf) > 0 && evbuffer_sendtofwd(hdr, session->buf, 0) != 0)
		return tcp_onsockdata(hdr, FLTEV_ONSOCKDATA, NULL, 0);
	return FLTRET_OK;
}

static enum FLT_RET tcp_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct tcp_session *session = hdr->user;

	if (session->connectok == 0)
	{
		SCLogInfo("TCP: svr not ready, delay.... ssid: %d", hdr->sessionid);
		if (evbuffer_add(session->buf, buff, len) != 0)
			return tcp_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		return FLTRET_OK;
	}

	if (buffer_sendtofwd(hdr, buff, len) != 0)
	{
		return tcp_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	return FLTRET_OK;
}

static enum FLT_RET tcp_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	const ForwardObject *obj = buff; assert(len == sizeof(obj));

	if (obj->cmd == FWDCMD_FORWARDDATA)
	{
		assert(obj->has_buffdata);

		int ret = hdr->reqcb(hdr, obj->buffdata.data, obj->buffdata.len);
		if (ret != 0)
		{
			return tcp_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
	}

	return FLTRET_OK;
}

static enum FLT_RET tcp_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct tcp_session *session = hdr->user;
	SCLogInfo("TCP: on socket close, ssid: %d", hdr->sessionid);

	tcp_session_free(session);
	hdr->user = NULL;
	return FLTRET_CLOSE;
}

//////////////////////////////////////////////////////////////////////////
// filter functions
int tcp_oninit()
{
	g_tcp_ondata_cb[FLTEV_ONCLIIN] = tcp_oncliin;
	g_tcp_ondata_cb[FLTEV_ONSVROK] = tcp_svrok;
	g_tcp_ondata_cb[FLTEV_ONSOCKDATA] = tcp_onsockdata;
	g_tcp_ondata_cb[FLTEV_ONFWDDATA] = tcp_onfwddata;
	g_tcp_ondata_cb[FLTEV_ONSOCKERROR] = tcp_onsockerr;

	return 0;
}

enum FLT_RET tcp_onpkt(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	return g_tcp_ondata_cb[ev](hdr, ev, buff, len);
}

int tcp_onfree()
{
	return 0;
}

struct packet_filter g_filter_tcp = { SVR_ID_TCP, "tcp parser", tcp_oninit, tcp_onpkt, tcp_onfree };

PROTOCOL_FILTER_OP(tcp)

