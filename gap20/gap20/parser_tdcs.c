
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
	uint8_t hd[4];		// �̶�Ϊ0xff 0xff 0xff 0xff
	uint32_t datalen;	// ��λ��ǰ�����ݵĳ��ȣ�������hd��length��
	uint8_t data[1];	// ����
};

struct tdcs20_tcp_frame_data
{
	uint8_t flag1;		// �̶�Ϊ0xef
	uint8_t flag2;		// �̶�Ϊ0xef
	uint16_t datalen;	// ��λ��ǰ
	uint8_t direction;	// �����룬ȡֵΪ0xf0��0xff
	uint8_t dstcode;	// Ŀ��������
	uint8_t stationcode1;	// վ�루�ͣ�
	uint8_t stationcode2;	// վ�루�ߣ�
	uint8_t infocode;	// ��Ϣ������
	uint8_t data[1];	// ����
};

/*
��1     �Ự������֡��ʽ
���    ����        �ֽ�   ����˵��
1       data_head   2     ֡ͷ�������ֽڣ��̶�ΪEFH,EFH
2       ��֡��       1     ��ֵ
3       ��ǰ֡��     1     ��1��ʼ���
4       data_len    2     ֵΪn����ʾdata��ĳ���,�����ֽڣ����ֽ���ǰ�����ֽ��ں�   n: 0x1122 -> mem(x86): 22 11 -> mem(mips): 11 22
5       Data        n     ��ʾ���͵�Ӧ�����ݸ����������Ϊ2048�ֽ�
6       data_tail   2     ֡β�������ֽڣ��̶�ΪFDH,FDH
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
��2    ��ʾ����Ϣ����ʽ
���   ����    �ֽ�  ����˵��
1      ����      1    ����������Ϣ��������
2      ������    1    ��������ͬһ��Ϣ�����µĲ�ͬ����
3      �汾��    1    ��������Э��İ汾������ָ��Ϊ01H
4      �ܰ���    2    �ܵ�Ҫ���͵���Ϣ��������
5      ��ǰ����  2    ���ڷ��͵���Ϣ����ţ���1��ʼ
6      �ֳ�      2    ��֡��Ϣ�����ֽ���(���������͡������롢�汾�š��ֳ����ܰ�������ǰ����)
7      ��Ϣ����  �ֳ��涨���ȵ���Ϣ
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
8AH������������Ϣ����ʽ����������������·�֡���վ����֮�䣩��
8BH�����������ִ��Ϣ����ʽ����������������·�֡���վ����֮�䣩��
8CH��ͨ��״̬��Ϣ����ʽ����������������·�ָ���֮�䣩��
8DH�����ԭ����Ϣ����ʽ����������������·�ָ���֮�䣩��
8EH��������Ϣ����ʽ����������������·�ָ���֮�䣩��
8FH���ɼ���ʾ��Ϣ����ʽ����������������·�ָ���֮�䣩��
90H���߼���ʾ��Ϣ����ʽ����������������·�֡���վ����֮�䣩��
91H����������Ϣ����ʽ����������������·�֡���վ����֮�䣩��
80H������ͼ��Ϣ����ʽ����������������·�֡���վ����֮�䣩��
81H���׶μƻ���Ϣ����ʽ��������·�֡���վ����֮�䣩��
82H�����滥����Ϣ����ʽ��������·�֡���վ����֮�䣩��
83H����վԤ��ȷ����ȡ����������·��ת����վ֮���Ԥ����Ϣ����
84H���ն˳���ά�����������·�֡���վ֮�䣩��
85H��վ�泵����������������·�֡���վ����֮�䣩��
86H��˦�ҳ�����������������·�֡���վ����֮�䣩��
87H��С���飨��������������·�֡���վ����֮�䣩��
88H��Ԥȷ������ͳһ������������������·�֡���վ����֮�䣩��
11H����ʱ���ٵ��������������������·�֡���վ����֮�䣩��
12H����ʱ���ٵ��������ִ����������������·�֡���վ����֮�䣩��
13H��1FH��Ԥ����Ϣ���ͣ������¹���ʱ���ã���������ȷ�Ϻ�תΪ��ʽ��Ϣ���ͣ���
79H��7FH���ɰ汾��Ϣ���͡�
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
	if (len == 1)	// ������
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
	//FLTEV_ONCLIIN �ͻ��˽�����
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
	//FLTEV_ONSVROK ���������ӳɹ�/ʧ��
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
	//FLTEV_ONSOCKDATA �յ����������ص�����
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


		// �����жϣ��ж�buf���Ƿ�������һ��TDCS�������
		while (evbuffer_get_length(session->buf) > 0)
		{
			int ret = session->lengthcb(session->buf);
			if (ret == -1)
			{
				SCLogInfo("tdcs v%d, length error", session->version);
				return tdcs_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
			if (ret == 0)
				return FLTRET_OK; // ������
			size_t tdcslen = ret;

			// ������ݵ���Ч��
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
	//FLTEV_ONFWDDATA �յ���˻�������
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
	//FLTEV_ONSOCKERROR ���ӹر�
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

