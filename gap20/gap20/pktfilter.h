#pragma once

#include "prefix.h"
#include "proto.h"
#include "svrid.h"
#include "servers.h"

struct iphdr;
struct tcphdr;
struct filter_header;
struct packet_filter;

// 触发ONPKTCB时的事件类型
enum FLT_EVENT
{
	FLTEV_ONCLIIN,		// 客户端连接进来，无参数
	FLTEV_ONSVROK,		// 服务端连接成功/失败，buff指向一个int类型的地址，其值为0表示失败，值为1表示成功

	FLTEV_ONSOCKDATA,	// 收到SOCKET的数据，buff指向数据内容，len为数据长度
	FLTEV_ONFWDDATA,	// 收到内端机的数据，buff指向对应的FowardObject对象，len一定为sizeof(void*)

	FLTEV_ONSOCKERROR,	// 网络中断，无参数
	FLTEV_COUNT
};

// ONPKTCB的返回值
enum FLT_RET
{
	FLTRET_OK,		// 正常过滤
	FLTRET_CLOSE,	// 关闭网络端的连接
};

// 路由的类型
enum ROUTE_TYPE
{
	ROUTE_MAPPED,
	ROUTE_TRANSPARENT
};

// 程序启动、退出时的回调
typedef int(*FLT_ONMAINCB)();

// 有数据包进来时，触发此函数
typedef enum FLT_RET(*FLT_ONPKTCB)(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);

// 模块内要添加一个转发服务端时，调用此函数进行添加或删除
typedef int(*FLT_SVRCB)(struct filter_header *hdr, struct server *svr);

// 模块内要向客户端/数据器发送数据时，调用此函数进行发送
typedef int(*FLT_SOCKCB)(struct filter_header *hdr, const void *buff, size_t len);

// 模块内要另一端进行包转发时，调用此函数进行转发
typedef int(*FLT_FWDCB)(struct filter_header *hdr, const void *buff, size_t len);

// 有转发端数据包进来时，触发此函数
typedef void(*FLT_ONFWDCB)(const void *buff, size_t len);

// 校验数据的协议类型，是不是当前过滤器的
typedef enum SVR_ID(*FLT_CHECKCB)(const void *buff, size_t len);

// filter header
struct filter_header
{
	struct server *svr;
	uint32_t sessionid;
	uint32_t timeout; // (sec)
	char *username;
	enum ROUTE_TYPE routetype;

	// callbackcb for parser
	FLT_SVRCB svr_add_cb;
	FLT_SVRCB svr_remove_cb;
	FLT_SOCKCB reqcb;
	FLT_SOCKCB respcb;
	FLT_FWDCB fwdcb;

	// ip/port/if info
	struct iphdr _ip, *ip;
	struct tcphdr _tcp, *tcp;
	struct udphdr _udp, *udp;
	uint32_t localip;
	uint16_t localport;
	char srcif[16];
	char dstif[16];
	char routename[32];

	struct tlvbox *tlv_in;	// ref ptr, don't free
	struct tlvbox *tlv_out;	// free on appsession_free

	void *user;  // point to parser's define memory
	void *private;
};

// 过滤器结构，用户模块负责填充，然后调用pktfilter_reg传入此结构
struct packet_filter
{
	enum SVR_ID svrid;
	char *name;
	FLT_ONMAINCB initcb;
	FLT_ONPKTCB onpktcb;
	FLT_ONMAINCB exitcb;
	FLT_CHECKCB checkcb;
};

// 注册过滤器，用户负责创建一个pktfilter结构并传入
int pktfilter_reg(struct packet_filter *filter);

// 取消过滤器
int pktfilter_unreg(struct packet_filter *filter);

// 初始化函数
int pktfilter_init();

// 退出函数
void pktfilter_exit();

// 获取指定的filter
struct packet_filter* pktfilter_get(enum SVR_ID svrid);

#define PROTOCOL_FILTER_DEFINE(proto, svr_id, initcb, onpktcb, exitcb, checkcb) \
    static struct packet_filter g_filter_##proto = {svr_id, initcb, onpktcb, exitcb, checkcb};

#define PROTOCOL_FILTER_REG(proto) \
    void parser_##proto##_pktfilter_reg(){pktfilter_reg(&g_filter_##proto);} 

#define PROTOCOL_FILTER_UNREG(proto) \
    void parser_##proto##_pktfilter_unreg(){pktfilter_unreg(&g_filter_##proto);}

#define PROTOCOL_FILTER_OP(proto) \
    PROTOCOL_FILTER_REG(proto)\
    PROTOCOL_FILTER_UNREG(proto)
