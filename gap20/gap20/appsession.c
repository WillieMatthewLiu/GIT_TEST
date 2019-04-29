#include <zebra.h>
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "vrf.h"
#include "vty.h"
#include "hash.h"

#include "tlvbox.h"
#include "app_common.h"
#include "pktfilter.h"
#include "gap_stgy.h"
#include "appsession.h"
#include "gapconfig.h"
#include "ipt_ctl.h"
#include "forwardcmd.h"

static struct list_head g_sessionpool;
static pthread_mutex_t g_sessionpool_lock_head;
static pthread_mutex_t g_sessionpool_lock_tail;

static pthread_rwlock_t g_sessionmap_lock;
static struct hash *g_sessionmap = NULL;
static struct list_head g_sessionlist = { 0 };	// used by sort

uint32_t appsession_genericid()
{
	static uint32_t sessionid = 100;

	sessionid++;
	if (sessionid > 100000000)
		sessionid = 100;

	if (RUN_AS_INNER())
		return (sessionid | (1 << 31));
	return sessionid;
}

int appsession_pool_init()
{
	pthread_mutex_init(&g_sessionpool_lock_head, NULL);
	pthread_mutex_init(&g_sessionpool_lock_tail, NULL);
	INIT_LIST_HEAD(&g_sessionpool);

	for (int i = 0; i < g_gapcfg->limit_usercount; i++)
	{
		struct app_session *session = SCMalloc(sizeof(struct app_session));
		memset(session, 0, sizeof(*session));
		list_add_tail(&session->_entry_pool, &g_sessionpool);
	}

	return 0;
}

struct app_session* appsession_pool_get()
{
	pthread_mutex_lock(&g_sessionpool_lock_head);
	struct app_session *session = list_first_entry_or_null(&g_sessionpool, struct app_session, _entry_pool);
	if (session != NULL) {
		list_del_init(&session->_entry_pool);
		session->invalid = 0;
	}
	pthread_mutex_unlock(&g_sessionpool_lock_head);

	return session;
}

int appsession_pool_put(struct app_session *session)
{
	pthread_mutex_lock(&g_sessionpool_lock_tail);
	memset(session, 0, sizeof(*session));
	list_add_tail(&session->_entry_pool, &g_sessionpool);
	pthread_mutex_unlock(&g_sessionpool_lock_tail);
	session->invalid = 1;
	return 0;
}

//////////////////////////////////////////////////////////////////////////
// session hash map
uint32_t inout_hashlist_id2session_hash(void *ptr)
{
	struct app_session *session = ptr;
	return session->id;
}

int inout_hashlist_id2session_compare(const void *p1, const void *p2)
{
	const struct app_session *session1 = p1;
	const struct app_session *session2 = p2;
	return session1->id == session2->id;
}

void inout_hashlist_id2session_onfree(void *ptr)
{
}

int sessionmap_init()
{
	int ret = appsession_pool_init();
	if (ret != 0)
		return -1;

	ret = pthread_rwlock_init(&g_sessionmap_lock, NULL);
	if (ret != 0)
		return -1;

	g_sessionmap = hash_create(inout_hashlist_id2session_hash,
		inout_hashlist_id2session_compare);
	if (g_sessionmap == NULL)
		goto ERR;

	INIT_LIST_HEAD(&g_sessionlist);
	return 0;
ERR:
	if (g_sessionmap != NULL)
	{
		hash_free(g_sessionmap);
		g_sessionmap = NULL;
	}

	pthread_rwlock_destroy(&g_sessionmap_lock);
	return -1;
}


int sessionmap_put(struct app_session *session)
{
	int ret = 0;

	pthread_rwlock_wrlock(&g_sessionmap_lock);
	hash_get(g_sessionmap, session, hash_alloc_intern);
	list_add(&session->_entry_global, &g_sessionlist);
	pthread_rwlock_unlock(&g_sessionmap_lock);

	if (session->flthdr.svr)
	{
		pthread_mutex_lock(&session->flthdr.svr->sessions_lock);
		os_longlonginc(&session->flthdr.svr->sessioncount, 1);
		list_add(&session->_entry_server, &session->flthdr.svr->sessions);
		pthread_mutex_unlock(&session->flthdr.svr->sessions_lock);
	}
	return ret;
}

struct app_session* sessionmap_get(uint32_t sessionid)
{
	pthread_rwlock_rdlock(&g_sessionmap_lock);
	struct app_session tmp = { .id = sessionid };
	struct app_session *ret = hash_lookup(g_sessionmap, &tmp);
	pthread_rwlock_unlock(&g_sessionmap_lock);
	return ret;
}

void sessionmap_remove(struct app_session *session)
{
	if (session->flthdr.svr)
	{
		pthread_mutex_lock(&session->flthdr.svr->sessions_lock);
		os_longlongdec(&session->flthdr.svr->sessioncount, 1);
		list_del(&session->_entry_server);
		pthread_mutex_unlock(&session->flthdr.svr->sessions_lock);
	}

	pthread_rwlock_wrlock(&g_sessionmap_lock);
	hash_release(g_sessionmap, session);
	list_del(&session->_entry_global);
	pthread_rwlock_unlock(&g_sessionmap_lock);
}

int sessionmap_free()
{
	hash_free(g_sessionmap);
	g_sessionmap = NULL;
	pthread_rwlock_destroy(&g_sessionmap_lock);
	return 0;
}

struct app_session *sessionmap_lookup(struct app_session *session)
{
	return hash_lookup(g_sessionmap, session);
}

static void sessionmap_close(struct hash_backet *bucket, void *arg)
{
	struct app_session *session = bucket->data;
	if (session->filter->svrid == SVR_ID_PCAP)
		return;

	if (arg && arg != session->mgr)
		return;

	sessionmap_postclose(session);
}

void sessionmap_closeall(struct sessionmgr *mgr)
{
	hash_iterate(g_sessionmap, sessionmap_close, mgr);
}

int sessionmap_postclose_byhdr(struct filter_header *hdr)
{
	struct app_session *session = OFFSET_OBJECT(hdr, app_session, flthdr);
	return sessionmap_postclose(session);
}

int sessionmap_freebysvr(struct server *svr)
{
	int ret = 0;
	struct sessionmgr *currmgr = sessionmgr_current();

	pthread_mutex_lock(&svr->sessions_lock);
	{
		struct list_head *tmp;
		struct list_head *n;
		list_for_each_safe(tmp, n, &svr->sessions)
		{
			struct app_session *session = list_entry(tmp, struct app_session, _entry_server);
			if (NULL == session)
				break;

			ret = sessionmap_postclose(session);
		}
	}
	pthread_mutex_unlock(&svr->sessions_lock);

	if (ret == 0)
	{
		int cnt = 50;	// 5s
		while (svr->sessioncount > 0 && cnt > 0)
		{
			os_sleep(100);
			cnt--;
		}

		if (svr->sessioncount > 0)
			ret = -1;
	}
	return ret;
}

void appsession_free(struct app_session *session)
{
	if (session == NULL)
	{		
		return;
	}
	if (session->invalid == 1)
	{		
		return;
	}

	session->state = SESSION_CLOSED;
	/*更新会话日志*/
	UPDATE_SESSION(session);
	if (session->filter->svrid != SVR_ID_SSL)
	{
		struct tlvbox *obj = tlvbox_create(0);
		if (obj != NULL)
		{
			tlv_init_from_appsession(session, obj, _FWDCMD_SOCK_CLOSED);
			filter_sendto_forward(&session->flthdr, obj, sizeof(obj));
			tlvbox_free(obj);
		}
	}

	if (session->flthdr.svr != NULL)
		time(&session->flthdr.svr->livetime);

	sessionmap_remove(session);

	if (SVRID_IS_UDP_FAMILY(session->filter->svrid))
	{
		if (session->flthdr.localport != 0 && session->fd_is_udp_svr == 0)
		{
			del_ipt_allowed_port(PORT_TYPE_UDP, session->flthdr.localport);
			udp_freeport_put(session->flthdr.localport);
			SCLogInfo("return udp port to udp port pool : %d", session->flthdr.localport);
		}
	}

	if (session->fd != 0 && session->fd_is_udp_svr == 0)
		sessionmgr_fdclose(session->mgr, session->fd);
	if (session->flthdr.username != NULL)
		SCFree(session->flthdr.username);
	if (session->flthdr.tlv_out)
		tlvbox_free(session->flthdr.tlv_out);
	if (session->flthdr.private)
		release_acl_data(session->flthdr.private);
	appsession_pool_put(session);
}

#define EST_INTERVAL 5
int est_ontimer(struct thread *t)
{
	pthread_rwlock_rdlock(&g_sessionmap_lock);
	struct app_session *tmp, *n;
	list_for_each_entry_safe(tmp, n, &g_sessionlist, _entry_global)
	{
		traffic_estimator_handle(&tmp->statistics, EST_INTERVAL);
	}
	pthread_rwlock_unlock(&g_sessionmap_lock);
	thread_add_timer(t->master, est_ontimer, NULL, EST_INTERVAL);

	return 0;
}

int est_ontimer_start(struct thread_master *master)
{
	thread_add_timer(master, est_ontimer, NULL, EST_INTERVAL);
	return 0;
}

int session_is_full()
{
	return (g_sessionmap->count >= g_gapcfg->limit_usercount);
}

int session_vtyquery(struct vty *vty, int offset, int count, int id)
{
#define S_SPLIT "\t"
	/*打印会话头字段*/
	if (id == 0) {
		vty_out(vty, "id"S_SPLIT"sessionid"S_SPLIT"innerifname"S_SPLIT"outerifname"S_SPLIT"user"S_SPLIT"route"S_SPLIT"outerip"S_SPLIT"outerport"S_SPLIT"innerip"S_SPLIT"innerport"S_SPLIT"protocol"S_SPLIT"application"S_SPLIT"createdtime%s",
			VTY_NEWLINE);
	}

	/* 打印待查询的会话数据 */
	int n = 0;
	struct app_session *s, *tmp;
	pthread_rwlock_rdlock(&g_sessionmap_lock);
	list_for_each_entry_safe(s, tmp, &g_sessionlist, _entry_global)
	{
		if (s->filter->svrid == SVR_ID_PCAP)
			continue;

		if (id == 0) {
			if ((n >= offset) && n < (offset + count)) {
				struct filter_header *flthdr = &s->flthdr;
				char sip[24]; addr2str(flthdr->ip->saddr, sip);
				int sport = flthdr->tcp ? flthdr->tcp->source : flthdr->udp->source;
				char dip[24]; addr2str(flthdr->ip->daddr, dip);
				int dport = flthdr->tcp ? flthdr->tcp->dest : flthdr->udp->dest;
				char ctime[100]; strftime(ctime, sizeof(ctime), "%Y-%m-%dT%H:%M:%SZ", localtime(&s->starttime));
				const char *proto = proto_strfromid(s->filter->svrid);
				int protocol = s->flthdr.tcp ? 6 : 17;
				struct acl_data *ad = (struct acl_data *)(flthdr->private);
				vty_out(vty, "%u"S_SPLIT"%u"S_SPLIT"%s"S_SPLIT"%s"S_SPLIT"%s"S_SPLIT"%s"S_SPLIT"%s"S_SPLIT"%d"S_SPLIT"%s"S_SPLIT"%d"S_SPLIT"%d"S_SPLIT"%s"S_SPLIT"%s%s",
					s->auto_id[0], s->id, flthdr->srcif, flthdr->dstif, ad->user, flthdr->routename, sip, sport, dip, dport, protocol, proto, ctime, VTY_NEWLINE);
			}
		}
		else {
			if (s->auto_id[0] == id) {
				struct filter_header *flthdr = &s->flthdr;
				struct traffic_counters *stats = &(s->statistics.stats);
				struct traffic_estimator *est = &(s->statistics.est);
				char sip[24]; addr2str(flthdr->ip->saddr, sip);
				int sport = flthdr->tcp ? flthdr->tcp->source : flthdr->udp->source;
				char dip[24]; addr2str(flthdr->ip->daddr, dip);
				int dport = flthdr->tcp ? flthdr->tcp->dest : flthdr->udp->dest;
				char ctime[100]; strftime(ctime, sizeof(ctime), "%Y-%m-%dT%H:%M:%SZ", localtime(&s->starttime));
				const char *proto = proto_strfromid(s->filter->svrid);
				struct acl_data *ad = (struct acl_data *)(flthdr->private);
				int protocol = s->flthdr.tcp ? 6 : 17;
				vty_out(vty, "0x%08X,%s,%s,%s,%s,%s,%d,%s,%d,%d,%s,%s,%u,%u,%llu,%u,%u,%u,%u,%u,%u,%d,%d%s",
					s->id, flthdr->srcif, flthdr->dstif, ad->user, flthdr->routename,
					sip, sport, dip, dport, protocol, proto, ctime,
					stats->inbytes, stats->outbytes, stats->inpkts, stats->outpkts,
					est->inbps, est->outbps, est->inpps, est->outpps,
					s->auto_id[0], ad->src_level, s->state, VTY_NEWLINE);
				pthread_rwlock_unlock(&g_sessionmap_lock);
				return 0;
			}
		}
	}
	pthread_rwlock_unlock(&g_sessionmap_lock);
	return 0;
}

static void _sessionmap_checktimout(struct hash_backet *bucket, void *arg)
{
	time_t now;
	struct app_session *session = bucket->data;

	time(&now);
	if ((session->id == 0)
		|| (session->filter->svrid == SVR_ID_SSL)
		|| (now - session->livetime < session->flthdr.timeout))
		return;

	sessionmap_postclose(session);
}
int session_checktimeout()
{
	hash_iterate(g_sessionmap, _sessionmap_checktimout, NULL);
	return 0;
}

