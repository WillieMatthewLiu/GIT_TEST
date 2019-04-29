
#include "app_common.h"
#include "servers.h"
#include "oscall.h"

enum SVR_TYPE nametotype(const char *name)
{
	if (strcmp(name, NAT_SVR_NAME) == 0)
		return SVR_TYPE_INTERNAL_NAT;
	if (strcmp(name, UDP_SVR_NAME) == 0)
		return SVR_TYPE_INTERNAL_UDP;
	if (strcmp(name, DTA_SVR_NAME) == 0)
		return SVR_TYPE_INTERNAL_DATA;
	if (strcmp(name, SSL_SVR_NAME) == 0)
		return SVR_TYPE_INTERNAL_SSL;
	return SVR_TYPE_APP;
}

struct server* server_new(enum SVR_ID id, const char *name, const char *localip, uint16_t localport, const char *dstip, uint16_t dstport)
{
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

	struct server *ret = SCMalloc(sizeof(struct server));
	if (ret == NULL)
		return NULL;

	memset(ret, 0, sizeof(*ret));
	ret->id = id;
	ret->type = nametotype(name);
	ret->name = name ? SCStrdup(name) : NULL;
	ret->localip = localip ? SCStrdup(localip) : NULL;
	ret->localport = localport;
	ret->dstip = dstip ? SCStrdup(dstip) : NULL;
	ret->dstport = dstport;
	pthread_mutex_init(&ret->sessions_lock, &attr);
	INIT_LIST_HEAD(&ret->sessions);
	time(&ret->livetime);

	if (ret->name == NULL || ret->localip == NULL || (dstip != NULL && ret->dstip == NULL))
	{
		server_free(ret);
		return NULL;
	}
	return ret;
}

void server_setfreecb(struct server *svr, SVR_FREEING_CB onfree, void *args)
{
	svr->onfree = onfree;
	svr->freeargs = args;
}

void server_free(struct server *svr)
{
	if (svr == NULL)
		return;

	if (svr->onfree != NULL)
		svr->onfree(svr, svr->freeargs);

	if (svr->name) SCFree(svr->name);
	if (svr->localip) SCFree(svr->localip);
	if (svr->dstip) SCFree(svr->dstip);
	if (svr->parent_acldata) SCFree(svr->parent_acldata);
	SCFree(svr);
}

static struct _SVR_ID_NAME_MAP
{
	enum SVR_ID id;
	const char *name;
} _svr_id_to_name_map[_SVR_ID_COUNT] = SVR_ID_TO_NAME_MAP;

enum SVR_ID server_idfromstr(const char *name)
{
	if (name == NULL)
		return _SVR_ID_NONE;
	for (int i = 0; i < countof(_svr_id_to_name_map); i++)
	{
		if (strcmp(_svr_id_to_name_map[i].name, name) == 0)
			return _svr_id_to_name_map[i].id;
	}

	SCLogError("invalid protocol string: %s", name);
	return _SVR_ID_NONE;
}

const char* server_strfromid(enum SVR_ID id)
{
	return _svr_id_to_name_map[id].name;
}

const char* proto_strfromid(enum SVR_ID id)
{
	if (id == SVR_ID_OPCSSDP || id == SVR_ID_OPCDATA) {
		id = SVR_ID_OPC;
	}
	else if (id == SVR_ID_FTPDATA) {
		id = SVR_ID_FTP;
	}
	else if (id == SVR_ID_SIPDATA) {
		id = SVR_ID_SIP;
	}
	else if (id == SVR_ID_RTSPDATA) {
		id = SVR_ID_RTSP;
	}
	return _svr_id_to_name_map[id].name;
}

// 将多个协议的字符串转为SVRID数组
int server_ids_fromstr(const char *protocols, uint8_t *svrids, int count)
{
	if (count < _SVR_ID_COUNT)
		return -1;
	memset(svrids, 0, count * sizeof(svrids[0]));

	if (strstr(protocols, "ALL") != NULL)
	{
		for (int id = 0; id < _SVR_ID_COUNT; id++)
			svrids[id] = 1;
	}

	if (strstr(protocols, "TCP") != NULL)
	{
		for (int id = SVR_ID_TCP; id < SVR_ID_UDP; id++)
			svrids[id] = 1;
	}

	if (strstr(protocols, "UDP") != NULL)
	{
		for (int id = SVR_ID_UDP; id < _SVR_ID_COUNT; id++)
			svrids[id] = 1;
	}

	char *s = SCStrdup(protocols);
	if (s == NULL)
		return -1;

	int n = 0;
	for (char *ctx, *iter = strtok_s(s, ",;", &ctx); iter != NULL; iter = strtok_s(NULL, ",;", &ctx))
	{
		enum SVR_ID id = server_idfromstr(iter);
		svrids[id] = 1;
	}

	SCFree(s);
	return 0;
}

int server_ids_hasid(enum SVR_ID id, const uint8_t *svrids, int count)
{
	if (count < _SVR_ID_COUNT)
		return 0;

	if (svrids[id] == 1)
		return 1;
	return 0;
}
