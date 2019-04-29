
#include "app_common.h"
#include "main_pciproxy.h"
#include "sockmgr.h"

// #define ENABLE_PCIPROXY

#ifdef ENABLE_PCIPROXY
#include "ac_shmem.h"
#else
int acse_shmem_init() { return 0; }
int acse_shmem_read_queue(int channel, void *buff, size_t len) { return 0; };
int acse_shmem_send_queue(int channel, void *buff, size_t len) { return 0; };
#endif

//////////////////////////////////////////////////////////////////////////
// 阻塞方式向PCI写数据，必须成功
static int pci_write(void *buff, size_t len)
{
	int ret = acse_shmem_send_queue(0, buff, len);
	//SCLogInfo("pci write, len: %d, ret: %d", (int)len, ret);
	return ret;
}

// 从PCI读数据，成功返回对应的字节数，读不到返回0
static int pci_read(void *buff, size_t len)
{
	int ret = acse_shmem_read_queue(0, buff, len);
	if (0 && ret > 0)	// 调试一秒打印一次，确认程序的主线程及PCI读数据是否运行中
	{
		static time_t t;
		time_t now; time(&now);
		if (now - t >= 1)
		{
			t = now;
			SCLogInfo("pci read, ret: %d", ret);
		}
	}
	return ret;
}


//////////////////////////////////////////////////////////////////////////
static struct array *g_channels = NULL;
static struct HashListTable_ *g_channels_map = NULL;
static struct connectionmgr *g_connmgr = NULL;
static struct event_base *g_base = NULL;

// 通道信息
struct proxy_channel
{
	char *ip;
	uint16_t port;

	char has_topci_data;
	char has_tosock_data;

	struct array *sessions;
};

// 会话结构
struct proxy_session
{
	evutil_socket_t fd;
	struct proxy_channel *channel;

	struct event *ev;

	uint64_t len_rx;
	uint64_t len_tx;
};

// PCI传输时的小块数据结构
struct pci_data_hdr
{
	uint16_t id;
	uint16_t len;
	char data[1];
};
#define PCI_DATA_HDR_LEN (sizeof(uint16_t)+sizeof(uint16_t))

// 预定义
struct proxy_channel* proxychannel_new();
void proxychannel_free(struct proxy_channel *channel);
static struct proxy_session* proxysession_new();
static void proxysession_free(struct proxy_session *session);

// 通道MAP相关
static uint32_t channel_hashmap_hash(struct HashListTable_ *map, void *ptr, uint16_t sz)
{
	struct proxy_channel *channel = ptr;
	return channel->port % map->array_size;
}
static char channel_hashmap_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct proxy_channel *channel1 = p1;
	struct proxy_channel *channel2 = p2;
	return channel1->port == channel2->port;
}
static void channel_hashmap_free(void *ptr)
{
	struct proxy_channel *channel = ptr;
	proxychannel_free(channel);
}
int channelmap_put(struct proxy_channel *channel)
{
	return HashListTableAdd(g_channels_map, channel, sizeof(channel));
}
struct proxy_channel *channelmap_get(int id)
{
	struct proxy_channel tmp; tmp.port = id;
	return HashListTableLookup(g_channels_map, &tmp, sizeof(&tmp));
}


// 通道分配
struct proxy_channel* proxychannel_new()
{
	struct proxy_channel *ret = NULL;
	ret = SCMalloc(sizeof(*ret));
	memset(ret, 0, sizeof(*ret));
	ret->sessions = array_init(1);
	return ret;
}

// 通道释放
void proxychannel_free(struct proxy_channel *channel)
{
	SCFree(channel->ip);

	for (int i = 0; i < array_count(channel->sessions); i++)
	{
		struct proxy_session *session = array_getat(channel->sessions, i);
		proxysession_free(session);
	}
	array_free(channel->sessions);
	SCFree(channel);
}

// 会话分配
static struct proxy_session* proxysession_new()
{
	struct proxy_session *session = NULL;
	session = SCMalloc(sizeof(*session)); memset(session, 0, sizeof(*session));
	return session;
}

// 会话释放
static void proxysession_free(struct proxy_session *session)
{
	array_find_and_remove(session->channel->sessions, session);
	event_del(session->ev);
	closesocket(session->fd);
	SCFree(session);
}

// 处理PCI的读写数据
static void disp_pci_event()
{
	int ret;
	char buff[16 * 1024];

	// 从PCI读数据
	ret = pci_read(buff, sizeof(buff));
	if (ret > PCI_DATA_HDR_LEN)
	{
		struct pci_data_hdr *hdr = (struct pci_data_hdr*)buff;
		hdr->id = ntohs(hdr->id);
		hdr->len = ntohs(hdr->len);
		if (hdr->len + PCI_DATA_HDR_LEN != ret)
			return;

		struct proxy_channel *channel = channelmap_get(hdr->id);
		assert(channel);

		for (int i = 0; i < array_count(channel->sessions); i++)
		{
			struct proxy_session *session = array_getat(channel->sessions, i);

			socket_syncsend(session->fd, hdr->data, hdr->len);
			session->len_tx += hdr->len;
		}
	}
}

// 客户端连接断开
static void on_error(struct proxy_session *session)
{
	SCLogInfo("on sock close, fd: %d, rx: %lld, tx: %lld", session->fd, session->len_rx, session->len_tx);

	proxysession_free(session);
}

// 收到了客户端的数据
static void on_data(evutil_socket_t fd, short event, void *args)
{
	struct proxy_session *session = args;

	if (event & EV_READ)
	{
		char buff[15 * 1024];
		struct pci_data_hdr *hdr = (struct pci_data_hdr*)buff;

		int ret = recv(fd, hdr->data, sizeof(buff), 0);
		if (ret <= 0)
		{
			on_error(session);
			return;
		}
		session->len_rx += ret;

		hdr->id = htons(session->channel->port);
		hdr->len = htons(ret);
		pci_write(hdr, ret + PCI_DATA_HDR_LEN);
	}
}

// 客户端连接进来
static void on_cliin(evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args)
{
	int ret;

	struct proxy_channel *channel = args;
	if (array_count(channel->sessions) > 0)
	{
		char *err = "channel fulled";
		socket_syncsend(fd, err, strlen(err));
		closesocket(fd);
		return;
	}

	struct sockaddr_in *paddr = (struct sockaddr_in*)cliaddr;
	SCLogInfo("on cli in, svr: %s:%d, fd: %d, cli: %s:%d", channel->ip, channel->port, fd, inet_ntoa(paddr->sin_addr), ntohs(paddr->sin_port));

	struct proxy_session *session = proxysession_new();

	struct event *ev = event_new(g_base, fd, EV_READ | EV_PERSIST, on_data, session);
	ret = event_add(ev, NULL);

	session->ev = ev;
	session->fd = fd;
	session->channel = channel;

	array_add(channel->sessions, session);
}

// 服务端连接成功
static void on_connok(evutil_socket_t fd, void *args)
{
	int ret;
	struct proxy_channel *channel = args;

	SCLogInfo("connect %s:%d, ret: %d", channel->ip, channel->port, fd);
	if (fd == -1)
		return;

	struct proxy_session *session = proxysession_new();

	struct event *ev = event_new(g_base, fd, EV_READ | EV_PERSIST, on_data, session);
	ret = event_add(ev, NULL);

	session->ev = ev;
	session->fd = fd;
	session->channel = channel;

	array_add(channel->sessions, session);
}

// 程序入口
int main_pciproxy(char *ip, char *port)
{
	int ret;

	ret = acse_shmem_init();
	SCLogInfo("acse_shmem_init, ret: %d", ret);

	g_channels = array_init(1);
	g_channels_map = HashListTableInit(10, channel_hashmap_hash, channel_hashmap_compare, channel_hashmap_free);
	g_base = event_base_new();
	g_connmgr = connmgr_new();

	for (char *ctx, *iter = strtok_s(port, ";", &ctx); iter != NULL; iter = strtok_s(NULL, ";", &ctx))
	{
		struct proxy_channel *channel = proxychannel_new();

		if (ip == NULL)
		{
			channel->ip = SCStrdup("0.0.0.0");
			channel->port = atoi(iter);

			ret = connmgr_addlistener(g_connmgr, channel->ip, channel->port, on_cliin, channel);
			SCLogInfo("listen %d, ret: %d", channel->port, ret);
		}
		else
		{
			channel->ip = SCStrdup(ip);
			channel->port = atoi(iter);

			ret = connmgr_addconnect(g_connmgr, channel->ip, channel->port, NULL, on_connok, channel);
			SCLogInfo("connecting %s:%d...", ip, channel->port, ret);
		}

		array_add(g_channels, channel);
		channelmap_put(channel);
	}

	while (1)
	{
		event_base_loop(g_base, EVLOOP_ONCE | EVLOOP_NONBLOCK);
		disp_pci_event();
	}

	return 0;
}
