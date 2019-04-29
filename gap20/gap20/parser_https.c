
#include "app_common.h"
#include "parser_https.h"

#include "pktfilter.h"
#include "parser_tcp.h"

#include "serialize.h"
#include "gapconfig.h"

struct https_session
{
	int connectok;
	int pktchecked;
	struct evbuffer *buf;
};

static enum SVR_ID https_check_data(const void *buff, size_t len);

struct https_session* https_session_new()
{
	struct https_session *session = SCMalloc(sizeof(struct https_session));
	if (session == NULL)
		return NULL;

	memset(session, 0, sizeof(*session));
	session->buf = evbuffer_new();
	if (session->buf == NULL)
	{
		SCFree(session);
		return NULL;
	}

	return session;
}

void https_session_free(struct https_session *session)
{
	if (session == NULL)
		return;
	evbuffer_free(session->buf);
	SCFree(session);
}

enum FLT_RET https_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONCLIIN 客户端进来了
	if (ev == FLTEV_ONCLIIN)
	{
		struct https_session *session = https_session_new();
		if (session == NULL)
			return FLTRET_CLOSE;
		hdr->user = session;

		// 只对外端机做协议检查
		if (hdr->svr == NULL)
			session->pktchecked = 1;

		SCLogInfo("HTTPS: on cli in, ssid: %d", hdr->sessionid);
		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSVROK 服务器连接成功/失败
	if (ev == FLTEV_ONSVROK)
	{
		struct https_session *session = hdr->user;

		int isok = *((int*)buff); assert(len == sizeof(isok));
		SCLogInfo("HTTPS: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

		if (isok == 0)
			return https_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);

		session->connectok = 1;
		if (evbuffer_get_length(session->buf) > 0)
			return https_ondata(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSOCKDATA 收到服务器返回的数据
	if (ev == FLTEV_ONSOCKDATA)
	{
		struct https_session *session = hdr->user;
		if (evbuffer_add(session->buf, buff, len) != 0)
			return https_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);

		// 检查协议有效性（只检查连接成功后，第一个数据包的有效性）
		if (session->pktchecked == 0)
		{
			session->pktchecked = 1;
			if (https_check_data(buff, len) == _SVR_ID_NONE)
				return https_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		if (session->connectok == 0)
		{
			SCLogInfo("HTTPS: svr not ready, delay.... ssid: %d", hdr->sessionid);
			return FLTRET_OK;
		}

		if (evbuffer_sendtofwd(hdr, session->buf, 0) != 0)
			return https_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONFWDDATA 收到外端机的数据
	if (ev == FLTEV_ONFWDDATA)
	{
		const ForwardObject *obj = buff; assert(len == sizeof(obj));

		if (obj->cmd == FWDCMD_FORWARDDATA)
		{
			assert(obj->has_buffdata);
			hdr->reqcb(hdr, obj->buffdata.data, obj->buffdata.len);
		}

		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSOCKERROR 连接关闭
	if (ev == FLTEV_ONSOCKERROR)
	{
		struct https_session *session = hdr->user;
		SCLogInfo("HTTPS: on socket close, ssid: %d", hdr->sessionid);

		https_session_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}

	return FLTRET_OK;
}

int https_oninit()
{
	return 0;
}

int https_onfree()
{
	return 0;
}

static enum SVR_ID https_check_data(const void *buff, size_t len)
{
	const uint8_t *p = buff;
	if (len > 2 && p[0] == 0x16 && p[1] == 0x03)
		return SVR_ID_HTTPS;
	if (len > 5 && p[0] == 0x80 && p[3] == 0x03 && p[4] == 0x03)
		return SVR_ID_HTTPS;
	return _SVR_ID_NONE;
}

static struct packet_filter g_filter_https = { SVR_ID_HTTPS, "https parser", https_oninit, https_ondata, https_onfree, https_check_data };

PROTOCOL_FILTER_OP(https)


