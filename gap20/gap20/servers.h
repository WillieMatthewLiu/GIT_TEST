#pragma once

#include "svrid.h"
#include "gap_ctl.h"

#define NAT_SVR_NAME "_nat tcp svr"
#define UDP_SVR_NAME "_udp common svr"
#define DTA_SVR_NAME "_data common server"
#define SSL_SVR_NAME "_ssl channel server"

enum SVR_TYPE
{
	_SVR_TYPE_NONE,
	SVR_TYPE_APP,
	SVR_TYPE_INTERNAL_NAT,
	SVR_TYPE_INTERNAL_UDP,
	SVR_TYPE_INTERNAL_DATA,
	SVR_TYPE_INTERNAL_SSL
};
struct server;
typedef void(*SVR_FREEING_CB)(struct server *svr, void *args);

struct server
{
	// baseinfo
	uint32_t parent_sesssionid;
	struct acl_data *parent_acldata;

	enum SVR_ID id;
	enum SVR_TYPE type;
	char *name;
	char *localip;
	uint16_t localport;
	char *dstip;
	uint16_t dstport;
	void *route;

	// session list
	uint64_t sessioncount;
	struct list_head sessions;
	pthread_mutex_t sessions_lock;

	// alive time
	time_t livetime;

	// callback on server freed
	SVR_FREEING_CB onfree;
	void *freeargs;

	int udp_svr_fd;
};

// 将HTTP、FTP等字符串，转为SVR_ID_HTTP、SVR_ID_FTP
enum SVR_ID server_idfromstr(const char *name);

// 将SVR_ID_XXX转为字符串
const char* server_strfromid(enum SVR_ID id);

//转成协议
const char* proto_strfromid(enum SVR_ID id);

// 创建一个server对象
struct server* server_new(enum SVR_ID id, const char *name, const char *localip, uint16_t localport, const char *dstip, uint16_t dstport);

// 设置释放时的通知函数
void server_setfreecb(struct server *svr, SVR_FREEING_CB onfree, void *args);

// 释放server对象
void server_free(struct server *svr);

// 将多个协议的字符串转为SVRID数组
int server_ids_fromstr(const char *protocols, uint8_t *svrids, int count);

// 判断server的ID，是否在其所附属的route的协议里面, 0: no  1: yes
int server_ids_hasid(enum SVR_ID id, const uint8_t *svrids, int count);

