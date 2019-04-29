
#include "app_common.h"
#include "main_fwddrv.h"

#include "sockmgr.h"
#include "serialize.h"
#include "oscall.h"

static struct connectionmgr *g_connmgr = NULL;

static evutil_socket_t g_forwardfd[4][2];
static struct sessionmgr *g_sessionmgr[4];
static uint32_t g_flux_sockread[4] = { 0 };

struct forward_session
{
	struct sessionmgr *mgr;
	evutil_socket_t fd;
	uint32_t id;
	struct evbuffer *buff;
};

// 收到了管道进来的数据
void fwdrv_ondata(const void *buff, size_t len, void *args)
{
	struct forward_session *session = args;
	g_flux_sockread[session->id] += (int)len;

	if (buff == NULL)
	{
		if (session->fd == g_forwardfd[session->id][0])
			g_forwardfd[session->id][0] = 0;
		else
			g_forwardfd[session->id][1] = 0;
		SCLogInfo("pipe disconnect...");
		sessionmgr_fdclose(session->mgr, session->fd);
		evbuffer_free(session->buff);
		closesocket(session->fd);
		SCFree(session);
		return;
	}

	//     // atao, test code
	//     static time_t t1 = 0, t2;
	//     static float flux = 0;
	//     flux += len;
	//     time(&t2);
	//     if (t2 - t1 >= 1)
	//     {
	//         SCLogInfo("mgr %d, total=%.2fM", session->fd, flux / 1024 / 1024);
	//         t1 = t2;
	//         flux = 0;
	//     }

	// 转发给另一端
	evutil_socket_t dstfd = (session->fd == g_forwardfd[session->id][0]) ? g_forwardfd[session->id][1] : g_forwardfd[session->id][0];
	if (dstfd == 0)
	{
		SCLogInfo("%d's pipe not ready", session->id);
		return;
	}
	socket_syncsend(dstfd, buff, len);
}

void fwdrv_cliin(evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args)
{
	int id = *((int*)args);
	SCLogInfo("pipe %d in...", id);
	struct sessionmgr *mgr;
	if (g_forwardfd[id][0] == 0)
	{
		g_forwardfd[id][0] = fd;
		mgr = g_sessionmgr[id];
	}
	else if (g_forwardfd[id][1] == 0)
	{
		g_forwardfd[id][1] = fd;
		mgr = g_sessionmgr[id];
	}
	else
	{
		closesocket(fd);
		return;
	}

	struct forward_session *session = SCMalloc(sizeof(struct forward_session));
	memset(session, 0, sizeof(*session));
	session->mgr = mgr;
	session->fd = fd;
	session->buff = evbuffer_new();
	session->id = id;
	sessionmgr_fdadd(mgr, fd, fwdrv_ondata, NULL, NULL, session);
	sessionmgr_setcpu(mgr, id);
}

int main_fwddrv()
{
	int ret = 0;
	memset(g_forwardfd, 0, sizeof(g_forwardfd));

	// connection mgr
	g_connmgr = connmgr_new();
	assert(g_connmgr);

	// session mgr
	g_sessionmgr[0] = sessionmgr_new();
	g_sessionmgr[1] = sessionmgr_new();
	g_sessionmgr[2] = sessionmgr_new();
	g_sessionmgr[3] = sessionmgr_new();

	// listen ports
	static int id1 = 0, id2 = 1, id3 = 2, id4 = 3;
	ret = connmgr_addlistener(g_connmgr, "0.0.0.0", 20001, fwdrv_cliin, &id1);
	ret = connmgr_addlistener(g_connmgr, "0.0.0.0", 20002, fwdrv_cliin, &id2);
	ret = connmgr_addlistener(g_connmgr, "0.0.0.0", 20003, fwdrv_cliin, &id3);
	ret = connmgr_addlistener(g_connmgr, "0.0.0.0", 20004, fwdrv_cliin, &id4);
	SCLogInfo("pipe server ready...");

	// run
	while (1)
	{
		os_sleep(1000);

		if (g_flux_sockread[0] > 0 || g_flux_sockread[1] > 0 || g_flux_sockread[2] > 0 || g_flux_sockread[3] > 0)
		{
			SCLogInfo("sockflux: %.2fM %.2fM %.2fM %.2fM",
				(float)g_flux_sockread[0] / 1024 / 1024, (float)g_flux_sockread[1] / 1024 / 1024,
				(float)g_flux_sockread[2] / 1024 / 1024, (float)g_flux_sockread[3] / 1024 / 1024);
			memset(g_flux_sockread, 0, sizeof(g_flux_sockread));
		}
	}

	// free
	connmgr_free(g_connmgr);

	return ret;
}
