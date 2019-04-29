
#include "app_common.h"
#include "parser_udp.h"
#include "parser_tcp.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"

struct udp_session
{
	int _none;
};

struct udp_session* udp_session_new()
{
	struct udp_session *session = SCMalloc(sizeof(struct udp_session));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	return session;
}

void udp_session_free(struct udp_session *session)
{
	SCFree(session);
}

enum FLT_RET udp_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONCLIIN 客户端进来了
	if (ev == FLTEV_ONCLIIN)
	{
		struct udp_session *session = udp_session_new();
		if (session == NULL)
		{
			return FLTRET_CLOSE;
		}
			
		hdr->user = session;
		SCLogInfo("udp: on cli in, ssid: %d, session = %p", hdr->sessionid, session);
		
		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSOCKDATA 收到服务器返回的数据
	if (ev == FLTEV_ONSOCKDATA)
	{
		struct udp_session* session = hdr->user;
	
		SCLogInfo("udp: on socket data, len: %d, ssid: %d, session = %p", (int)len, hdr->sessionid, session);

		// TODO: 提取UDP payload的数据，再生成一个新的eth、ip头（避免协议攻击），然后发给另一端
		// 发收到的数据
		if(buffer_sendtofwd(hdr, buff, len) != 0)
		{
			return udp_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}			

		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONFWDDATA 收到外端机的数据
	if (ev == FLTEV_ONFWDDATA)
	{
		const ForwardObject* obj = buff; 
		assert(len == sizeof(obj));

		if (obj->cmd == FWDCMD_FORWARDDATA)
		{
			assert(obj->has_buffdata);

			SCLogInfo("udp: on fwd data, len: %d, ssid: %d, session = %p", (int)obj->buffdata.len, hdr->sessionid, hdr->user);
			int ret = hdr->reqcb(hdr, obj->buffdata.data, obj->buffdata.len);
			if (ret != 0)
			{				
				return udp_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}				
		}

		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSOCKERROR 连接关闭
	if (ev == FLTEV_ONSOCKERROR)
	{
		struct udp_session* session = hdr->user;
		SCLogInfo("udp: on socket close, ssid: %d, session = %p", hdr->sessionid, session);

		udp_session_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}
	
	return FLTRET_OK;
}

int udp_oninit()
{
	return 0;
}

int udp_onfree()
{
	return 0;
}

static struct packet_filter g_filter_udp = { SVR_ID_UDP, "udp outer parser", udp_oninit, udp_ondata, udp_onfree };

void parser_udp_pktfilter_reg()
{
	pktfilter_reg(&g_filter_udp);
}

void parser_udp_pktfilter_unreg()
{
	pktfilter_unreg(&g_filter_udp);
}