
#include "app_common.h"
#include "parser_tdcs.h"
#include "parser_tcp.h"
#include "serialize.h"
#include "pktfilter.h"
#include "gapconfig.h"

typedef int(*TDCS_LENGTH_CB)(struct evbuffer *buf);
typedef int(*TDCS_DATA_CB)(const void *buff, size_t len);

struct tdcs_session
{
	int version;
	TDCS_LENGTH_CB lengthcb;
	TDCS_DATA_CB datacb;

	struct evbuffer *buf;
	uint16_t pktlen;
};

static uint16_t tdcs_short_swap(uint16_t n)
{
	uint8_t *p = (uint8_t*)&n;
	return (p[1] << 8) | p[0];
}

static uint32_t tdcs_int_swap(uint32_t n)
{
	uint8_t *p = (uint8_t*)&n;
	return (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | (p[0] << 0);
}

static uint8_t g_tdcs20_head[] = { 0xff, 0xff, 0xff, 0xff };
static uint8_t g_tdcs20_tail[] = { 0xfd };
static uint8_t g_tdcs30_head[] = { 0xef, 0xef };
static uint8_t g_tdcs30_tail[] = { 0xfd, 0xfd };


#define TDCS20_MAX_DATALEN (2048)
#define TDCS20_MAX_PKTLEN (TDCS20_MAX_DATALEN + 9)

#define TDCS30_MAX_DATALEN (2048)
#define TDCS30_MAX_PKTLEN (TDCS30_MAX_DATALEN + 8)


#pragma pack(push, 1)

struct tdcs20_tcp_frame
{
	uint8_t hd[4];		// 固定为0xff 0xff 0xff 0xff
	uint32_t datalen;	// 低位在前，数据的长度（不包括hd、length）
	uint8_t data[1];	// 数据
};

struct tdcs20_tcp_frame_data
{
	uint8_t flag1;		// 固定为0xef
	uint8_t flag2;		// 固定为0xef
	uint16_t datalen;	// 高位在前
	uint8_t direction;	// 方向码，取值为0xf0、0xff
	uint8_t dstcode;	// 目的区域码
	uint8_t stationcode1;	// 站码（低）
	uint8_t stationcode2;	// 站码（高）
	uint8_t infocode;	// 信息分类码
	uint8_t data[1];	// 数据
};

/*
表1     会话层数据帧格式
序号    内容        字节   内容说明
1       data_head   2     帧头，两个字节，固定为EFH,EFH
2       总帧数       1     数值
3       当前帧号     1     从1开始编号
4       data_len    2     值为n，表示data域的长度,两个字节，低字节在前，高字节在后   n: 0x1122 -> mem(x86): 22 11 -> mem(mips): 11 22
5       Data        n     表示发送的应用数据个数，长度最长为2048字节
6       data_tail   2     帧尾，两个字节，固定为FDH,FDH
*/
struct tdcs30_tcp_frame
{
	uint8_t hd[2];
	uint8_t count;
	uint8_t current;
	uint16_t datalen;
	uint8_t data[1];
	//uint8_t tail[2];
};


/*
表2    表示层信息包格式
序号   内容    字节  内容说明
1      类型      1    用于区分信息包的类型
2      功能码    1    用于区分同一信息类型下的不同功能
3      版本号    1    用来区分协议的版本，本版指定为01H
4      总包数    2    总的要发送的信息包的数量
5      当前包号  2    正在发送的信息包序号，从1开始
6      字长      2    该帧信息流总字节数(不包括类型、功能码、版本号、字长、总包数、当前包号)
7      信息正文  字长规定长度的信息
*/
struct tdcs30_tcp_frame_data
{
	uint8_t type;
	uint8_t func;
	uint8_t ver;
	uint8_t count;
	uint8_t current;
	uint8_t datalen;
	uint8_t data[1];
};

#pragma pack(push, 1)


/*
8AH：调度命令信息包格式（适用于铁道部、路局、车站各级之间）；
8BH：调度命令回执信息包格式（适用于铁道部、路局、车站各级之间）；
8CH：通信状态信息包格式（适用于铁道部、路局各级之间）；
8DH：晚点原因信息包格式（适用于铁道部、路局各级之间）；
8EH：控制信息包格式（适用于铁道部、路局各级之间）；
8FH：采集表示信息包格式（适用于铁道部、路局各级之间）；
90H：逻辑表示信息包格式（适用于铁道部、路局、车站各级之间）；
91H：到发点信息包格式（适用于铁道部、路局、车站各级之间）；
80H：运行图信息包格式（适用于铁道部、路局、车站各级之间）；
81H：阶段计划信息包格式（适用于路局、车站各级之间）；
82H：交叉互控信息包格式（适用于路局、车站各级之间）；
83H：邻站预告确认与取消（适用于路局转发车站之间的预告信息）；
84H：终端车次维护命令（适用于路局、车站之间）；
85H：站存车（适用于铁道部、路局、车站各级之间）；
86H：甩挂车（适用于铁道部、路局、车站各级之间）；
87H：小编组（适用于铁道部、路局、车站各级之间）；
88H：预确报（运统一）（适用于铁道部、路局、车站各级之间）；
11H：临时限速调度命令（适用于铁道部、路局、车站各级之间）；
12H：临时限速调度命令回执（适用于铁道部、路局、车站各级之间）；
13H—1FH：预留信息类型（开发新功能时暂用，经铁道部确认后转为正式信息类型）；
79H—7FH：旧版本信息类型。
*/
uint8_t g_tdcs30_types[0xff] = { 0 };

// -1: error, 0: no enough data, N: ok
int check_tdcs_length_v2(struct evbuffer *buf)
{
	if (evbuffer_get_length(buf) < 8)
		return 0;

	char hd[8];
	evbuffer_copyout(buf, hd, 8);

	uint32_t len = *((uint32_t*)(hd + 4));
	len = tdcs_int_swap(len);
	if (len == 1)	// 心跳包
		return 8;

	len += 8;
	if (evbuffer_get_length(buf) < len)
		return 0;

	//SCLogInfo("tdcs2 len ok, len=%d", len);
	return len;
}

int check_tdcs_length_v3(struct evbuffer *buf)
{
	if (evbuffer_get_length(buf) < 8)
		return 0;

	char hd[8];
	evbuffer_copyout(buf, hd, 8);

	uint16_t len = *((uint16_t*)(hd + 4));
	len = tdcs_short_swap(len);

	len += 8;
	if (evbuffer_get_length(buf) < len)
		return 0;

	//SCLogInfo("tdcs3 len ok, len=%d", len);
	return len;
}

int check_tdcs_data_v2(const void *buff, size_t len)
{
	const struct tdcs20_tcp_frame *frame = buff;
	int framelen = frame->datalen;

	if (len > TDCS20_MAX_PKTLEN)
		return -1;

	framelen = tdcs_int_swap(framelen);
	if (framelen > TDCS20_MAX_DATALEN)
		return -1;

	if (framelen == 1)
		return 0;

	if (memcmp(frame->data, "\xef\xef", 2) != 0)
		return -1;

	if (memcmp((const char*)frame->data + framelen - 1, g_tdcs20_tail, sizeof(g_tdcs20_tail)) != 0)
		return -1;

	const struct tdcs20_tcp_frame_data *data = (void*)frame->data;
	//	SCLogInfo("tdcs2 data ok, len=%d, code=%02X, info=%02X", len, data->dstcode, data->infocode);
	return 0;
}

int check_tdcs_data_v3(const void *buff, size_t len)
{
	const struct tdcs30_tcp_frame *frame = buff;
	int framelen = frame->datalen;

	if (len > TDCS30_MAX_PKTLEN)
		return -1;

	if (memcmp((const char*)buff + len - 2, g_tdcs30_tail, sizeof(g_tdcs30_tail)) != 0)
		return -1;

	framelen = tdcs_short_swap(framelen);
	if (framelen > TDCS30_MAX_DATALEN)
		return -1;

	const struct tdcs30_tcp_frame_data *data = (void*)frame->data;
	// 		if (data->ver != 0x01)
	// 			return -1;
	// 		if (g_tdcs30_types[data->type] == 0)
	// 			return -1;
	SCLogInfo("tdcs3 data ok, len=%d, ver=%02X, type=%02X %d(%d)", len, data->ver, data->type, data->current, data->count);

	return 0;
}

struct tdcs_session* tdcs_session_new()
{
	struct tdcs_session *session = SCMalloc(sizeof(struct tdcs_session));
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

void tdcs_session_free(struct tdcs_session *session)
{
	if (session == NULL)
		return;
	evbuffer_free(session->buf);
	SCFree(session);
}

enum FLT_RET tdcs_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONCLIIN 客户端进来了
	if (ev == FLTEV_ONCLIIN)
	{
		struct tdcs_session *session = tdcs_session_new();
		if (session == NULL)
			return FLTRET_CLOSE;
		hdr->user = session;
		SCLogInfo("TDCS: on cli in, ssid: %d", hdr->sessionid);
		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSVROK 服务器连接成功/失败
	if (ev == FLTEV_ONSVROK)
	{
		struct tdcs_session *session = hdr->user;

		int isok = *((int*)buff); assert(len == sizeof(isok));
		SCLogInfo("TDCS: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

		if (isok == 0)
			return tdcs_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSOCKDATA 收到服务器返回的数据
	if (ev == FLTEV_ONSOCKDATA)
	{
		struct tdcs_session *session = hdr->user;
		if (evbuffer_add(session->buf, buff, len) != 0)
			return tdcs_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);

		//SCLogInfo("TDCS: on socket data, len: %d, ssid: %d", (int)len, hdr->sessionid);
		if (session->lengthcb == NULL)
		{
			if (memcmp(buff, g_tdcs20_head, sizeof(g_tdcs20_head)) == 0)
			{
				session->version = 2;
				session->lengthcb = check_tdcs_length_v2;
				session->datacb = check_tdcs_data_v2;
			}
			else if (memcmp(buff, g_tdcs30_head, sizeof(g_tdcs30_head)) == 0)
			{
				session->version = 3;
				session->lengthcb = check_tdcs_length_v3;
				session->datacb = check_tdcs_data_v3;
			}
		}
		if (session->lengthcb == NULL)
		{
			SCLogInfo("invalid tdcs2 or tdcs3 data");
			return FLTRET_CLOSE;
		}


		// 长度判断，判断buf里是否收足了一个TDCS块的数据
		while (evbuffer_get_length(session->buf) > 0)
		{
			int ret = session->lengthcb(session->buf);
			if (ret == -1)
			{
				SCLogInfo("tdcs v%d, length error", session->version);
				return tdcs_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
			if (ret == 0)
				return FLTRET_OK; // 继续收
			size_t tdcslen = ret;

			// 检查数据的有效性
			char tdcsbf[TDCS30_MAX_PKTLEN];
			evbuffer_remove(session->buf, tdcsbf, tdcslen);
			ret = session->datacb(tdcsbf, tdcslen);
			if (ret != 0)
			{
				SCLogInfo("tdcs v%d, data error", session->version);
				return tdcs_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}

			//SCLogInfo("TDCS: on tdcs block, len: %d, ssid: %d", (int)tdcslen, hdr->sessionid);
			if (buffer_sendtofwd(hdr, tdcsbf, tdcslen) != 0)
				return tdcs_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
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

			//SCLogInfo("TDCS: on fwd data, len: %d, ssid: %d", (int)obj->buffdata.len, hdr->sessionid);
			hdr->reqcb(hdr, obj->buffdata.data, obj->buffdata.len);
		}

		return FLTRET_OK;
	}

	//////////////////////////////////////////////////////////////////////////
	//FLTEV_ONSOCKERROR 连接关闭
	if (ev == FLTEV_ONSOCKERROR)
	{
		struct tdcs_session *session = hdr->user;
		SCLogInfo("TDCS: on socket close, ssid: %d", hdr->sessionid);

		tdcs_session_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}

	return FLTRET_OK;
}

// int load_testbin(const char *path, struct evbuffer *bf)
// {
// 	int total = 0;
// 	char buff[1024];
// 
// 	FILE *f = fopen(path, "rb");
// 	if (f == NULL)
// 		return -1;
// 
// 	while (1)
// 	{
// 		int n = fread(buff, 1, sizeof(buff), f);
// 		if (n <= 0)
// 			break;
// 		evbuffer_add(bf, buff, n);
// 		total += n;
// 	}
// 	fclose(f);
// 	return total;
// }
// 
// void tdcs_local_test()
// {
// 	struct evbuffer *buf = evbuffer_new();
// 	load_testbin("c:\\users\\atao\\desktop\\tdcs20_1.bin", buf);
// 	load_testbin("c:\\users\\atao\\desktop\\tdcs20_2.bin", buf);
// 	load_testbin("c:\\users\\atao\\desktop\\tdcs30_1.bin", buf);
// 	load_testbin("c:\\users\\atao\\desktop\\tdcs30_2.bin", buf);
// 	load_testbin("c:\\users\\atao\\desktop\\ctc_1.bin", buf);
// 	load_testbin("c:\\users\\atao\\desktop\\ctc_2.bin", buf);
// 
// 	int oklen = 0;
// 	while (evbuffer_get_length(buf) > 0)
// 	{
// 		int len = check_tdcs_length(buf);
// 		if (len == -1)
// 		{
// 			SCLogInfo("length error, oklen: %d, rest len: %d", oklen, evbuffer_get_length(buf));
// 			break;
// 		}
// 
// 		char buff[4096];
// 		evbuffer_remove(buf, buff, len);
// 
// 		int ok = check_tdcs_data(buff, len);
// 		if (ok == -1)
// 		{
// 			SCLogInfo("data breaked, oklen: %d, rest len: %d", oklen, evbuffer_get_length(buf));
// 			break;
// 		}
// 		oklen += len;
// 	}
// 
// 	evbuffer_free(buf);
// }

int tdcs_oninit()
{
	//	tdcs_local_test();
	for (int i = 0x11; i <= 0x1F; i++)
		g_tdcs30_types[i] = 1;
	for (int i = 0x79; i <= 0x98; i++)
		g_tdcs30_types[i] = 1;
	return 0;
}

int tdcs_onfree()
{
	return 0;
}

enum SVR_ID tdcs_check_data(const void *buff, size_t len)
{
	// TDCS20
	if (len > 4 && memcmp(buff, "\xff\xff\xff\xff", 4) == 0)
		return SVR_ID_TDCS;
	// TDCS30
	if (len > 2 && memcmp(buff, "\xef\xef", 2) == 0)
		return SVR_ID_TDCS;
	return _SVR_ID_NONE;
}

struct packet_filter g_filter_tdcs = { SVR_ID_TDCS, "tdcs parser", tdcs_oninit, tdcs_ondata, tdcs_onfree, tdcs_check_data };

PROTOCOL_FILTER_OP(tdcs)

