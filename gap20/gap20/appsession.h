#pragma once
#include "db_mysql.h"
#include "pktfilter.h"
#include "gap_traffic_est.h"
enum SESSION_STATE
{
	SESSION_NULL,
	SESSION_CONNECTING,
	SESSION_READY,
	SESSION_DISCONNECTING,
	SESSION_CLOSED
};
struct app_session
{
	struct list_head _entry_pool;
	struct list_head _entry_server;
	struct list_head _entry_global;

	struct sessionmgr *mgr;			// sessionmgr's ptr
	evutil_socket_t fd;				// session's socket
	uint8_t fd_is_udp_svr;

	uint32_t id;					// session' id
	uint32_t auto_id[2];            //id of database table on inner and outer
	uint32_t parent_id;					// session' id
	struct packet_filter *filter;	// session's filter

	int guessok;					// guess proto on first data packet, if guessok, set guessok=1
	enum SESSION_STATE state;		// session's state

	time_t starttime;
	time_t livetime;				// session's last active time
	struct filter_header flthdr;	// filter's hdr

	int flowlimited;				// flow controling 0/1
	struct traffic_statistics statistics;/* 会话流量统计 */

	uint8_t invalid;
};
#define OFFSET_OBJECT(p, st, m) (struct st*)((char*)p - ((char*)&((struct st*)0)->m))

#define INSERT_SESSION(s) do{\
		if (SVR_ID_SSL == s->filter->svrid) break;\
		struct filter_header *flthdr = &s->flthdr;\
		struct traffic_counters *stats = &(s->statistics.stats);\
		struct traffic_estimator *est = &(s->statistics.est);\
		char sip[24];addr2str(flthdr->ip->saddr,sip);\
		int sport = flthdr->tcp?flthdr->tcp->source:flthdr->udp->source;\
		char dip[24];addr2str(flthdr->ip->daddr,dip);\
		int dport = flthdr->tcp?flthdr->tcp->dest:flthdr->udp->dest;\
		char ctime[100];strftime(ctime, sizeof(ctime), "%Y-%m-%dT%H:%M:%SZ", localtime(&s->starttime));\
		const char *proto = proto_strfromid(s->filter->svrid);\
		int protocol = s->flthdr.tcp?6:17;\
		struct acl_data *ad = (struct acl_data *)(flthdr->private);\
		INSERT_SESSION_LOG(s->id,flthdr->srcif,flthdr->dstif, ad->user,flthdr->routename,s->state, sip, ntohs(sport),dip,ntohs(dport),protocol,proto,\
			stats->inbytes, stats->outbytes, stats->inpkts, stats->outpkts, est->max_inbps, est->max_outbps, est->max_inpps, est->max_outpps,ctime,s->auto_id);\
	}while(0)

#define UPDATE_SESSION(s) do{\
		if (SVR_ID_SSL == s->filter->svrid) break;\
		struct traffic_counters *stats = &(s->statistics.stats);\
		struct traffic_estimator *est = &(s->statistics.est);\
		const char *proto = proto_strfromid(s->filter->svrid);\
		unsigned long u1=est->max_inbps,u2=est->max_outbps,u3=est->max_inpps,u4=est->max_outpps;\
		if (s->state!=SESSION_CLOSED){u1=est->inbps,u2=est->outbps,u3=est->inpps,u4=est->outpps;}\
		UPDATE_SESSION_LOG(s->auto_id,proto,s->state,\
			stats->inbytes, stats->outbytes, stats->inpkts, stats->outpkts, u1, u2, u3, u4);\
	}while(0)

int appsession_pool_init();
struct app_session* appsession_pool_get();
int appsession_pool_put(struct app_session *session);
int sessionmap_init();
struct app_session* sessionmap_get(uint32_t sessionid);
int sessionmap_put(struct app_session *session);
void sessionmap_remove(struct app_session *session);
struct app_session *sessionmap_lookup(struct app_session *session);
int est_ontimer_start(struct thread_master *master);
int session_is_full();

void sessionmap_closeall(struct sessionmgr *mgr);

