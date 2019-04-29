
#include "app_common.h"
#include "sockmgr.h"
#include "oscall.h"
#include "ipt_ctl.h"
#include "servers.h"
#define LIBEVENT_DEFAULT_WATERMARK 1*1024*1024
#define LIBEVENT_DEFAULT_TIMER 1

static struct timeval g_timertv = { LIBEVENT_DEFAULT_TIMER, 0 };
static pthread_key_t g_sessionmgr_tls = NULL;

struct mgrsocket
{
	int type;	// 0: svrsock(listen)   1: clisock(connect)
	struct connectionmgr *mgr;
	struct event *ev;
	evutil_socket_t fd;

	LISTENER_CB svrcb;
	CONNECT_CB clicb;
	void *cbargs;

	char *listenip;
	uint16_t listenport;
};

struct connectionmgr
{
	struct event_base *base;
	struct event *timerev;

	pthread_t evthread;
	pthread_rwlock_t lock;
	HashListTable *socks;

	TIMER_CB timercb;
	void *timerargs;

	int ready;
};

void connmgr_oncliin(evutil_socket_t svrfd, short ev, void *args)
{
	struct mgrsocket *svrsock = args;
	assert(svrsock->type == 0);

	struct sockaddr_in addr = { 0 };
	socklen_t len = sizeof(addr);
	evutil_socket_t fd = accept(svrfd, (struct sockaddr*)&addr, &len);
	if (fd == -1)
	{
		SCLogInfo("connmgr_oncliin fd == -1");
		return;
	}

	SCLogInfo("connmgr_oncliin listenip = %s listenport = %d", svrsock->listenip , svrsock->listenport);

	svrsock->svrcb(fd, (struct sockaddr*)&addr, len, svrsock->cbargs);
}

void connmgr_onconnok(evutil_socket_t clifd, short ev, void *args)
{
	struct mgrsocket *clisock = args;
	assert(clisock->type == 1);

	if (ev & EV_WRITE && send(clifd, NULL, 0, 0) == -1)
		ev = EV_TIMEOUT;

	if (ev & EV_WRITE)
		clisock->clicb(clifd, clisock->cbargs);

	if (ev & EV_TIMEOUT)
	{
		closesocket(clifd);
		clisock->clicb(-1, clisock->cbargs);
	}

	pthread_rwlock_wrlock(&clisock->mgr->lock);
	HashListTableRemove(clisock->mgr->socks, clisock, sizeof(clisock));
	event_free(clisock->ev);
	pthread_rwlock_unlock(&clisock->mgr->lock);
	SCFree(clisock);
}

void connmgr_ontimer(evutil_socket_t fd, short ev, void *args)
{
	struct connectionmgr *mgr = args;
	if (mgr->timercb != NULL)
		mgr->timercb(mgr->timerargs);
}

void* connmgr_loopthread(void *args)
{
	struct connectionmgr *mgr = args;
	SCLogInfo("connmgr running: %p", mgr);
	mgr->ready = 1;
	int ret = event_base_loop(mgr->base, 0);
	SCLogInfo("connmgr finish: %p %d", mgr, ret);
	return NULL;
}

uint32_t hashlist_connmgr_hash(HashListTable *tb, void *ptr, uint16_t aa)
{
	struct mgrsocket *s = ptr;
	return (uint32_t)(s->fd % tb->array_size);
}

char hashlist_connmgr_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct mgrsocket *s1 = p1;
	struct mgrsocket *s2 = p2;
	return (s1->fd == s2->fd);
}

void hashlist_connmgr_onfree(void *ptr)
{
}

void* sockmgr_alloc(size_t sz)
{
	return SCMalloc(sz);
}

void* sockmgr_realloc(void *ptr, size_t sz)
{
	return SCRealloc(ptr, sz);
}

void sockmgr_free(void *ptr)
{
	SCFree(ptr);
}

struct connectionmgr* connmgr_new()
{
#ifdef _WIN32
	WSADATA data; WSAStartup(MAKEWORD(2, 2), &data);
	evthread_use_windows_threads();
#else
	evthread_use_pthreads();
#endif
	event_set_mem_functions(sockmgr_alloc, sockmgr_realloc, sockmgr_free);

	struct connectionmgr *mgr = NULL;

	int ret, addok = 0, threadok = 0, mutexok = 0, ok = 0;
	do
	{
		mgr = SCMalloc(sizeof(struct connectionmgr));
		if (mgr == NULL)
			break;
		memset(mgr, 0, sizeof(*mgr));

		mgr->socks = HashListTableInit(1024, hashlist_connmgr_hash, hashlist_connmgr_compare, hashlist_connmgr_onfree);
		if (mgr->socks == NULL)
			break;

		mgr->base = event_base_new();
		if (mgr->base == NULL)
			break;

		mgr->timerev = event_new(mgr->base, -1, EV_READ | EV_PERSIST, connmgr_ontimer, mgr);
		if (mgr->timerev == NULL)
			break;

		ret = event_add(mgr->timerev, &g_timertv);
		if (ret != 0)
			break;
		addok = 1;

		ret = pthread_rwlock_init(&mgr->lock, NULL);
		if (ret != 0)
			break;
		mutexok = 1;

		ret = pthread_create(&mgr->evthread, NULL, connmgr_loopthread, mgr);
		if (ret != 0)
			break;

#ifdef USER_MEM_ALLOC
		ThreadMemInit("", mgr->evthread);
#endif
		threadok = 1;

		while (mgr->ready == 0)
			os_sleep(1);

		ok = 1;
	} while (0);

	if (ok == 0 && mgr != NULL)
	{
		if (threadok == 1)
			pthread_kill(mgr->evthread, 0);

		if (mutexok == 1)
			pthread_rwlock_destroy(&mgr->lock);

		if (addok == 1)
			event_del(mgr->timerev);

		if (mgr->timerev != NULL)
			event_free(mgr->timerev);

		if (mgr->base != NULL)
			event_base_free(mgr->base);

		if (mgr->socks != NULL)
			HashListTableFree(mgr->socks);

		SCFree(mgr);
		mgr = NULL;
	}
	return mgr;
}

int connmgr_settimercb(struct connectionmgr *mgr, struct timeval *tv, TIMER_CB timercb, void *args)
{
	if (mgr == NULL)
		return -1;
	mgr->timercb = timercb;
	mgr->timerargs = args;
	event_del(mgr->timerev);
	event_add(mgr->timerev, tv);
	return 0;
}

int tcpudp_port_test(const char *ip, uint16_t port, int type)
{
	int ret;
	evutil_socket_t fd = 0;

	if (type != SOCK_STREAM && type != SOCK_DGRAM)
		return -1;

	while (1)
	{
		fd = socket(AF_INET, type, (type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP);
		if (fd != -1)
			break;
	}

	struct sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_port = ntohs(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
	closesocket(fd);
	if (ret != 0)
		return -1;
	return 0;
}

evutil_socket_t new_udp_service(const char *localaddr, uint16_t localport, void *agrs)
{
	if (localaddr == NULL)
	{
		return -1;
	}

	if (inet_addr(localaddr) == INADDR_NONE)
		return -1;
	evutil_socket_t fd = 0;
	int ret, ok = 0;
	do
	{
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (fd == -1)
			break;
		int on = 1;
		//setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));

		struct sockaddr_in addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_port = ntohs(localport);
		addr.sin_addr.s_addr = inet_addr(localaddr);

		ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));

		add_ipt_allowed_port(PORT_TYPE_UDP, localport);
		if (ret != 0)
			break;
		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (fd != 0)
			closesocket(fd);
		return -1;
	}
	return fd;
}

int connmgr_addlistener(struct connectionmgr *mgr, const char *localaddr, uint16_t localport, LISTENER_CB cb, void *args)
{
	if (mgr == NULL)
	{
		return -1;
	}
		
	if (localaddr == NULL)
	{
		return -1;
	}
		
	if (inet_addr(localaddr) == INADDR_NONE)
	{
		return -1;
	}
		
	if (cb == NULL)
	{
		return -1;
	}
		

	evutil_socket_t fd = 0;
	struct mgrsocket *svr = NULL;

	int ret, addok = 0, ok = 0;
	do
	{
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fd == -1)
		{
			break;
		}
			

		int on = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));

		struct sockaddr_in addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_port = ntohs(localport);
		addr.sin_addr.s_addr = inet_addr(localaddr);
		ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
		if (ret != 0)
		{
			SCLogError("on connmgr_addlistener, bind failed, %s:%d, errno: %d, errstr: %s", localaddr, localport, errno, strerror(errno));
			break;
		}
		else
		{
			SCLogError("on connmgr_addlistener, bind success, %s:%d", localaddr, localport);		
		}			

		ret = listen(fd, 100);
		if (ret != 0)
		{
			break;
		}			

		ret = evutil_make_socket_nonblocking(fd);
		if (ret != 0)
		{
			break;
		}
			
		svr = SCMalloc(sizeof(struct mgrsocket));
		if (svr == NULL)
		{
			break;
		}
			
		memset(svr, 0, sizeof(*svr));
		svr->type = 0;
		svr->mgr = mgr;
		svr->ev = event_new(mgr->base, fd, EV_READ | EV_PERSIST, connmgr_oncliin, svr);
		svr->fd = fd;
		svr->svrcb = cb;
		svr->cbargs = args;
		svr->listenip = SCStrdup(localaddr);
		svr->listenport = localport;
		if (svr->ev == NULL)
		{
			break;
		}
			
		ret = event_add(svr->ev, NULL);
		if (ret != 0)
		{
			break;
		}
			
		addok = 1;

		pthread_rwlock_wrlock(&mgr->lock);
		ret = HashListTableAdd(mgr->socks, svr, sizeof(svr));
		pthread_rwlock_unlock(&mgr->lock);
		if (ret != 0)
		{
			break;
		}			

		add_ipt_allowed_port(PORT_TYPE_TCP, localport);
		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (svr != NULL)
		{
			if (addok == 1)
			{
				event_del(svr->ev);
			}
				
			if (svr->ev != NULL)
			{
				event_free(svr->ev);
			}

			SCFree(svr);
		}

		if (fd != 0)
		{
			closesocket(fd);
		}

		return -1;
	}

	return 0;
}

int connmgr_removelistener(struct connectionmgr *mgr, const char *localaddr, uint16_t localport)
{
	int ret = -1;
	if (mgr == NULL)
		return ret;
	if (localaddr == NULL)
		return ret;
	if (inet_addr(localaddr) == INADDR_NONE)
		return ret;

	pthread_rwlock_wrlock(&mgr->lock);
	for (HashListTableBucket *iter = HashListTableGetListHead(mgr->socks); iter != NULL; iter = HashListTableGetListNext(iter))
	{
		struct mgrsocket *sock = HashListTableGetListData(iter);
		if (sock->type != 0)
			continue;
		if (sock->listenport != localport || strcmp(sock->listenip, localaddr) != 0)
			continue;
		del_ipt_allowed_port(PORT_TYPE_TCP, localport);
		HashListTableRemove(mgr->socks, sock, sizeof(sock));
		event_del(sock->ev);
		SCFree(sock->listenip);
		closesocket(sock->fd);
		event_free(sock->ev);
		SCFree(sock);
		ret = 0;
		break;
	}
	pthread_rwlock_unlock(&mgr->lock);
	return ret;
}


int connmgr_addconnect(struct connectionmgr *mgr, const char *dstaddr, uint16_t dstport, struct timeval *timeout, CONNECT_CB cb, void *args)
{
	if (mgr == NULL)
		return -1;
	if (dstaddr == NULL)
		return -1;
	if (inet_addr(dstaddr) == INADDR_NONE)
		return -1;
	if (cb == NULL)
		return -1;

	struct timeval tv = { 30, 0 };
	if (timeout == NULL)
		timeout = &tv;

	struct sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_port = ntohs(dstport);
	addr.sin_addr.s_addr = inet_addr(dstaddr);

	evutil_socket_t fd = 0;
	struct mgrsocket *cli = NULL;

	pthread_rwlock_wrlock(&mgr->lock);
	int ret, addok = 0, ok = 0;
	do
	{
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fd == -1)
			break;

		ret = evutil_make_socket_nonblocking(fd);
		if (ret != 0)
			break;

		ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
#ifdef _WIN32
		if (ret == -1 && WSAGetLastError() != WSAEWOULDBLOCK)
#else
		if (ret == -1 && errno != EINPROGRESS)
#endif
			break;

		cli = SCMalloc(sizeof(struct mgrsocket));
		if (cli == NULL)
			break;
		memset(cli, 0, sizeof(*cli));
		cli->type = 1;
		cli->mgr = mgr;
		cli->ev = event_new(mgr->base, fd, EV_WRITE, connmgr_onconnok, cli);
		cli->fd = fd;
		cli->clicb = cb;
		cli->cbargs = args;
		if (cli->ev == NULL)
			break;

		ret = event_add(cli->ev, timeout);
		if (ret != 0)
			break;
		addok = 1;

		ret = HashListTableAdd(mgr->socks, cli, sizeof(cli));
		if (ret != 0)
			break;

		ok = 1;
	} while (0);
	pthread_rwlock_unlock(&mgr->lock);

	if (ok == 0)
	{
		if (cli != NULL)
		{
			if (addok == 1)
				event_del(cli->ev);

			if (cli->ev != NULL)
				event_free(cli->ev);

			SCFree(cli);
		}

		if (fd != 0)
			closesocket(fd);

		return -1;
	}
	return 0;
}

evutil_socket_t connmgr_syncconnect(const char *dstaddr, uint16_t dstport)
{
	if (dstaddr == NULL)
		return -1;
	if (inet_addr(dstaddr) == INADDR_NONE)
		return -1;

	struct sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_port = ntohs(dstport);
	addr.sin_addr.s_addr = inet_addr(dstaddr);

	evutil_socket_t fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1)
		return -1;

	int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	if (ret == 0)
		return fd;

	closesocket(fd);
	return -1;
}

void connmgr_free(struct connectionmgr *mgr)
{
	void *tmp;

	if (mgr == NULL)
		return;
	pthread_rwlock_rdlock(&mgr->lock);
	for (HashListTableBucket *iter = HashListTableGetListHead(mgr->socks); iter != NULL; iter = HashListTableGetListNext(iter))
	{
		struct mgrsocket *sock = HashListTableGetListData(iter);
		event_del(sock->ev);
	}
	event_del(mgr->timerev);
	pthread_rwlock_unlock(&mgr->lock);

	pthread_join(mgr->evthread, &tmp);

	pthread_rwlock_wrlock(&mgr->lock);
	for (HashListTableBucket *iter = HashListTableGetListHead(mgr->socks); iter != NULL; iter = HashListTableGetListNext(iter))
	{
		struct mgrsocket *sock = HashListTableGetListData(iter);
		if (sock->type == 0)
			SCFree(sock->listenip);
		closesocket(sock->fd);
		event_free(sock->ev);
		SCFree(sock);
	}
	HashListTableFree(mgr->socks);
	pthread_rwlock_unlock(&mgr->lock);
	pthread_rwlock_destroy(&mgr->lock);

	event_free(mgr->timerev);
	event_base_free(mgr->base);
	SCFree(mgr);
}

enum GAP_SESSION_TYPE
{
	TCP_SOCK_SESSION,
	UDP_SOCK_SESSION,
};

struct sessionmgr;
struct socksession
{
	struct sessionmgr *mgr;
	evutil_socket_t fd;

	struct event *rev;
	struct event *wev;
	struct evbuffer *wbf;

	ONUDPDATA_CB udpdatacb;
	UDP_TIME_OUT_CB timeoutcb;
	ONDATA_CB datacb;
	ONWRITE_CB writecb;
	void *cbargs;

	int enablewindow;
	int window;
	int dofree;
	struct timeval timeout;
};

struct socksession* socksession_new()
{
	struct socksession *session = SCMalloc(sizeof(struct socksession));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	return session;
}

void socksession_free(struct socksession *session)
{
	if (session->rev != NULL)
	{
		event_del(session->rev);
		event_free(session->rev);
	}

	if (session->wev != NULL)
	{
		event_del(session->wev);
		event_free(session->wev);
	}

	if (session->wbf != NULL)
		evbuffer_free(session->wbf);

	if (session->fd != 0)
	{
		closesocket(session->fd);
	}

	SCFree(session);
}


//////////////////////////////////////////////////////////////////

struct sessionmgr
{
	struct event_base *base;

	struct event *timerev;
	pthread_t evthread;

	pthread_rwlock_t lock;
	HashListTable *sessions;

	time_t livetime;
	TIMER_CB timercb;
	void *timerargs;

	int ready;
	int id;
};

void mgr_udpdata_in(evutil_socket_t svrfd, short ev, void *args)
{
	struct sockaddr_in cliaddr = { 0 };
	socklen_t cliaddrlen = sizeof(cliaddr);

	struct socksession *psessionmgr = (struct socksession *)args;

	char recvbuf[1500] = { 0 };
	if (ev == EV_TIMEOUT)
	{
		psessionmgr->timeoutcb(psessionmgr->mgr, svrfd, args);
	}
	else
	{
		size_t datalen = recvfrom(svrfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)(&cliaddr), &cliaddrlen);

		if (psessionmgr != NULL && psessionmgr->dofree == 0);
		{
			psessionmgr->udpdatacb((void *)recvbuf, datalen, psessionmgr->fd, (struct sockaddr *)(&cliaddr), cliaddrlen, psessionmgr->cbargs);
		}
	}
}

void sessionmgr_onevent(evutil_socket_t fd, short ev, void *args)
{
	struct socksession* session = args;
	assert(session->fd == fd);

	if (ev & EV_READ)
	{
		int n = 0;
		char buff[16 * 1024] = { 0 };
		
		if (session->enablewindow)
		{
			int readlen = (session->window > sizeof(buff)) ? sizeof(buff) : session->window;
			if (readlen <= 0)
			{
				// remove read event until next call sessionmgr_fdwindow
				event_del(session->rev);
				return;
			}

			n = recv(fd, buff, readlen, 0);
			if (n > 0)
			{
				session->window -= n;
			}
		}
		else
		{
			n = recv(fd, buff, sizeof(buff), 0);
		}
		
		if (n <= 0)
		{
			if (session->dofree == 0)
			{
				session->datacb(NULL, 0, session->cbargs);
			}
			else
			{
				socksession_free(session);
			}
		}
		else
		{
			session->datacb(buff, n, session->cbargs);
		}
	}

	if (ev & EV_WRITE)
	{
		size_t restlen;

		evbuffer_write_atmost(session->wbf, fd, -1);
		restlen = evbuffer_get_length(session->wbf);

		if ((session->writecb != NULL) && (session->dofree == 0))
		{
			session->writecb(restlen, session->cbargs);
		}

		if (restlen == 0)
		{
			event_del(session->wev);

			if (session->dofree == 1)
			{
				socksession_free(session);
			}
		}
	}

	if (ev & EV_TIMEOUT)
	{
		session->datacb(NULL, 0, session->cbargs);
	}
}

void sessionmgr_ontimer(evutil_socket_t svrfd, short ev, void *args)
{
	struct sessionmgr *mgr = args;
	time(&mgr->livetime);
	if (mgr->timercb != NULL)
		mgr->timercb(mgr->timerargs);
}

void* sessionmgr_loopthread(void *args)
{
	struct sessionmgr *mgr = args;
	pthread_setspecific(g_sessionmgr_tls, mgr);
	SCLogInfo("sessionmgr running: %d %p", mgr->id, mgr);
	mgr->ready = 1;
	int ret = event_base_loop(mgr->base, 0);
	SCLogInfo("sessionmgr finish: %d %p %d", mgr->id, mgr, ret);
	return NULL;
}

uint32_t sessionmgr_hashlist_hash(HashListTable *tb, void *ptr, uint16_t aa)
{
	struct socksession *session = ptr;
	return ((uint32_t)session->fd) % tb->array_size;
}

char sessionmgr_hashlist_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct socksession *ss1 = p1;
	struct socksession *ss2 = p2;
	return ss1->fd == ss2->fd;
}

void sessionmgr_hashlist_onfree(void *ptr)
{
}

static int g_sessionmgr_autoid = 0;
struct sessionmgr* sessionmgr_new()
{
	evthread_use_pthreads();
	event_set_mem_functions(sockmgr_alloc, sockmgr_realloc, sockmgr_free);

	if (g_sessionmgr_tls == NULL)
		pthread_key_create(&g_sessionmgr_tls, NULL);

	struct sessionmgr *mgr = NULL;
	int ret, addok = 0, threadok = 0, mutexok = 0, ok = 0;
	do
	{
		mgr = SCMalloc(sizeof(struct sessionmgr));
		if (mgr == NULL)
			break;
		memset(mgr, 0, sizeof(*mgr));

		mgr->sessions = HashListTableInit(1024, sessionmgr_hashlist_hash, sessionmgr_hashlist_compare, sessionmgr_hashlist_onfree);
		if (mgr->sessions == NULL)
			break;

		mgr->id = g_sessionmgr_autoid++;
		mgr->ready = 0;
		mgr->base = event_base_new();
		if (mgr->base == NULL)
			break;

		mgr->timerev = event_new(mgr->base, -1, EV_READ | EV_PERSIST, sessionmgr_ontimer, mgr);
		if (mgr->timerev == NULL)
			break;

		ret = event_add(mgr->timerev, &g_timertv);
		if (ret != 0)
			break;
		addok = 1;

		ret = pthread_rwlock_init(&mgr->lock, NULL);
		if (ret != 0)
			break;
		mutexok = 1;
		ret = pthread_create(&mgr->evthread, NULL, sessionmgr_loopthread, mgr);
		if (ret != 0)
			break;

#ifdef USER_MEM_ALLOC
		ThreadMemInit("", mgr->evthread);
#endif
		threadok = 1;

		while (mgr->ready == 0)
			os_sleep(1);

		ok = 1;
	} while (0);

	if (ok == 0 && mgr != NULL)
	{
		if (threadok == 1)
			pthread_kill(mgr->evthread, 0);

		if (mutexok == 1)
			pthread_rwlock_destroy(&mgr->lock);

		if (addok == 1)
			event_del(mgr->timerev);

		if (mgr->timerev != NULL)
			event_free(mgr->timerev);

		if (mgr->base != NULL)
			event_base_free(mgr->base);

		if (mgr->sessions != NULL)
			HashListTableFree(mgr->sessions);

		SCFree(mgr);
		mgr = NULL;
	}

	return mgr;
}

struct sessionmgr* sessionmgr_current()
{
	if (g_sessionmgr_tls == NULL)
		return NULL;
	return pthread_getspecific(g_sessionmgr_tls);
}

int sessionmgr_setpriority(struct sessionmgr *mgr, int level)
{
	if (mgr == NULL)
		return -1;
	struct sched_param sched;
	sched.sched_priority = -1;
	return pthread_setschedparam(mgr->evthread, level, &sched);
}

int sessionmgr_setcpu(struct sessionmgr *mgr, int cpu)
{
	if (mgr == NULL)
		return -1;
#ifndef _WIN32
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	return pthread_setaffinity_np(mgr->evthread, sizeof(mask), &mask);
#endif
	return 0;
}

int sessionmgr_getid(struct sessionmgr *mgr)
{
	if (mgr == NULL)
		return -1;
	return mgr->id;
}

int sessionmgr_getlivetime(struct sessionmgr *mgr)
{
	if (mgr == NULL)
		return -1;
	return mgr->livetime;
}

int sessionmgr_settimercb(struct sessionmgr *mgr, struct timeval *tv, TIMER_CB timercb, void *args)
{
	if (mgr == NULL)
		return -1;
	if (tv == NULL)
		return -1;
	mgr->timercb = timercb;
	mgr->timerargs = args;
	event_del(mgr->timerev);
	event_add(mgr->timerev, tv);
	return 0;
}

int sessionmgr_fdadd(struct sessionmgr *mgr, evutil_socket_t fd, ONDATA_CB datacb, ONWRITE_CB writecb, struct timeval *tv, void *args)
{
	if (mgr == NULL)
		return -1;

	evutil_make_socket_nonblocking(fd);

	struct socksession *session = NULL;

	int ret, ok = 0;
	do
	{
		session = socksession_new();
		if (session == NULL)
			break;
		session->mgr = mgr;
		session->fd = fd;
		session->datacb = datacb;
		session->writecb = writecb;
		session->cbargs = args;
		session->rev = event_new(session->mgr->base, fd, EV_READ | EV_PERSIST, sessionmgr_onevent, session);
		session->wev = event_new(session->mgr->base, fd, EV_WRITE | EV_PERSIST, sessionmgr_onevent, session);
		session->wbf = evbuffer_new();
		if (tv != NULL)
			session->timeout = *tv;
		if (session->rev == NULL || session->wev == NULL || session->wbf == NULL)
			break;

		ret = event_add(session->rev, tv);
		if (ret != 0)
			break;

		pthread_rwlock_wrlock(&mgr->lock);
		ret = HashListTableAdd(session->mgr->sessions, session, sizeof(session));
		pthread_rwlock_unlock(&mgr->lock);
		if (ret != 0)
			break;

		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (session != NULL)
			socksession_free(session);
		return -1;
	}
	return 0;
}

int sessionmgr_udpfdadd(struct sessionmgr *mgr, evutil_socket_t fd, ONUDPDATA_CB datacb, UDP_TIME_OUT_CB timeoutcb, struct timeval *tv, void *agrs)
{

	if (mgr == NULL)
		return -1;
	int ret, ok = 0;

	struct socksession *session = NULL;

	do
	{
		ret = evutil_make_socket_nonblocking(fd);
		if (ret != 0)
			break;


		session = socksession_new();
		if (session == NULL)
			break;
		session->mgr = mgr;
		session->fd = fd;
		session->udpdatacb = datacb;
		session->timeoutcb = timeoutcb;
		session->cbargs = agrs;

		struct event *ev = event_new(mgr->base, fd, EV_READ | EV_PERSIST, mgr_udpdata_in, session);
		if (ev == NULL)
			break;
		session->rev = ev;
		ret = event_add(session->rev, tv);
		if (ret != 0)
			break;

		pthread_rwlock_wrlock(&mgr->lock);
		ret = HashListTableAdd(session->mgr->sessions, session, sizeof(session));
		pthread_rwlock_unlock(&mgr->lock);
		if (ret != 0)
			break;
		ok = 1;
	} while (0);

	if (ok == 0)
	{
		if (session != NULL)
		{
			event_del(session->rev);
			if (session->rev != NULL)
				event_free(session->rev);
			SCFree(session);
		}

		if (fd != 0)
			closesocket(fd);
		return -1;
	}
	return 0;
}

int sessionmgr_fdsend(struct sessionmgr *mgr, evutil_socket_t fd, const void *buff, size_t len)
{
	if (mgr == NULL)
		return -1;

	struct socksession tmp; tmp.fd = fd;
	//pthread_rwlock_rdlock(&mgr->lock);
	struct socksession *session = HashListTableLookup(mgr->sessions, &tmp, sizeof(&tmp));
	//pthread_rwlock_unlock(&mgr->lock);
	if (session == NULL)
		return -1;
	event_add(session->wev, NULL);
	evbuffer_add(session->wbf, buff, len);
	return (int)evbuffer_get_length(session->wbf);
}

int sessionmgr_fdsend_buff(struct sessionmgr *mgr, evutil_socket_t fd, struct evbuffer *buff)
{
	if (mgr == NULL)
		return -1;

	struct socksession tmp; tmp.fd = fd;
	//pthread_rwlock_rdlock(&mgr->lock);
	struct socksession *session = HashListTableLookup(mgr->sessions, &tmp, sizeof(&tmp));
	//pthread_rwlock_unlock(&mgr->lock);
	if (session == NULL)
		return -1;
	event_add(session->wev, NULL);
	evbuffer_add_buffer(session->wbf, buff);
	return (int)evbuffer_get_length(session->wbf);
}

int sessionmgr_fdwindow(struct sessionmgr *mgr, evutil_socket_t fd, int window)
{
	struct socksession tmp; tmp.fd = fd;
	pthread_rwlock_wrlock(&mgr->lock);
	struct socksession *session = HashListTableLookup(mgr->sessions, &tmp, sizeof(&tmp));
	pthread_rwlock_unlock(&mgr->lock);
	if (session == NULL)
		return -1;

	if (window == -1)
	{
		session->enablewindow = 0;
		session->window = 0;
	}
	else
	{
		session->enablewindow = 1;
		session->window = window;
	}

	if (session->timeout.tv_sec == 0 && session->timeout.tv_sec == 0)
		event_add(session->rev, NULL);
	else
		event_add(session->rev, &session->timeout);
	return 0;
}

int _sessionmgr_arrfind(evutil_socket_t *arr, int count, evutil_socket_t fd)
{
	int isexcept = 0;
	for (int i = 0; i < count; i++)
	{
		if (arr[i] == fd)
			return i;
	}
	return -1;
}

int sessionmgr_fdwindow_all(struct sessionmgr *mgr, int window, evutil_socket_t *except_fds, int count)
{
	for (HashListTableBucket *iter = HashListTableGetListHead(mgr->sessions); iter != NULL; iter = HashListTableGetListNext(iter))
	{
		struct socksession *session = HashListTableGetListData(iter);

		if (_sessionmgr_arrfind(except_fds, count, session->fd) >= 0)
			continue;

		if (window == -1)
		{
			session->enablewindow = 0;
			session->window = 0;
		}
		else
		{
			session->enablewindow = 1;
			session->window = window;
		}

		if (session->timeout.tv_sec == 0 && session->timeout.tv_sec == 0)
			event_add(session->rev, NULL);
		else
			event_add(session->rev, &session->timeout);
	}
}

int sessionmgr_fdclose(struct sessionmgr *mgr, evutil_socket_t fd)
{
	if (mgr == NULL)
		return -1;

	struct socksession tmp; tmp.fd = fd;
	pthread_rwlock_wrlock(&mgr->lock);
	struct socksession *session = HashListTableLookup(mgr->sessions, &tmp, sizeof(&tmp));
	if (session) HashListTableRemove(mgr->sessions, &tmp, sizeof(&tmp));
	pthread_rwlock_unlock(&mgr->lock);
	if (session == NULL)
		return -1;

	if (session->wbf != NULL && evbuffer_get_length(session->wbf) > 0)
		session->dofree = 1;
	else
		socksession_free(session);
	return 0;
}

void sessionmgr_free(struct sessionmgr *mgr)
{
	if (mgr == NULL)
		return;

	event_del(mgr->timerev);

	void *tmp;
	pthread_join(mgr->evthread, &tmp);

	HashListTableFree(mgr->sessions);
	event_free(mgr->timerev);

	pthread_rwlock_destroy(&mgr->lock);

	event_base_free(mgr->base);
	SCFree(mgr);
}


int socket_syncsend(evutil_socket_t fd, const void *buff, size_t len)
{
	int ret = 0;
	uint32_t sends = 0;
	while (sends < len)
	{
		int n = send(fd, (const char*)buff + sends, (int)len - sends, 0);

		if (n > 0)
		{
			sends += n;
			continue;
		}

		// n <= 0
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
		{
			os_sleep(1);
			continue;
		}

		ret = -1;
		break;
	}
	return ret;
}

int socket_syncrecv(evutil_socket_t fd, const void *buff, size_t len)
{
	int ret = 0;
	uint32_t recvs = 0;
	while (recvs < len)
	{
		int n = recv(fd, (const char*)buff + recvs, (int)len - recvs, 0);
		if (n > 0)
		{
			recvs += n;
			continue;
		}

		// n <= 0
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
		{
			os_sleep(1);
			continue;
		}

		ret = -1;
		break;
	}
	return ret;
}
