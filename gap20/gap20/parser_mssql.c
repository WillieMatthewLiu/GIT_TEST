/* App Layer Parser for Mssql */
#include "app_common.h"
#include "parser_mssql.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "nlkernel.h"
#include "parser_tcp.h"
#include "db_agent.h"
#include "gap_stgy.h"
#include "cmd_common.h"
#include "main_inouter.h"
#include "parser_orcl.h"
#include "parser_common.h"
#include "db_mysql.h"
#include "gap_cmd_group.h"
#include "gap_cmd_dbsecurity.h"


/* Packet Types */
#define TDS_QUERY_PKT        1 
#define TDS_LOGIN_PKT        2
#define TDS_RPC_PKT          3
#define TDS_RESP_PKT         4
#define TDS_RAW_PKT          5
#define TDS_ATTENTION_PKT    6
#define TDS_BULK_DATA_PKT    7 
#define TDS_OPEN_CHN_PKT     8
#define TDS_CLOSE_CHN_PKT    9
#define TDS_RES_ERROR_PKT   10
#define TDS_LOG_CHN_ACK_PKT 11
#define TDS_ECHO_PKT        12
#define TDS_LOGOUT_CHN_PKT  13
#define TDS_TRANS_MGR_PKT   14
#define TDS_QUERY5_PKT      15  
#define TDS_LOGIN7_PKT      16 
#define TDS_SSPI_PKT        17
#define TDS_PRELOGIN_PKT    18
#define TDS_INVALID_PKT     19
#define TDS_TLS_PKT         23

#define is_valid_tds_type(x) (((x) >= TDS_QUERY_PKT && (x) < TDS_INVALID_PKT) || x == TDS_TLS_PKT)

/* BOOL Types */
#define TRUE                1
#define FALSE               0
#define RET_OK              0
#define RET_ERROR          -1

/* Packet Para */
#define HEAD_LEN            8
#define QURE_PKT_HEAD_LEN  22
#define QURE_PKT_OFFSET    30
#define TYPE_OFFSET         0
#define LENGHT_OFFSET       2
#define TLS_LENGTH_OFFSET   3
#define CONNECT_FAILURE    0

/*db operation*/
#define  UPDATE "UP"
#define  INSERT "IN"
#define  DELETE "DE"
#define  SELECT "SE"
#define  CREATE "CR"
#define  DROP   "DR"

#define  OP_UPDATE      "update"
#define  OP_INSERT      "insert"
#define  OP_DELETE      "delete"
#define  OP_SELECT      "select"
#define  OP_CREATE      "create"
#define  OP_DROP        "drop"

#define  MSSQL          "SQLSERVER"

static FLT_ONPKTCB g_mssql_ondata_cb[FLTEV_COUNT] = { 0 };
static enum FLT_RET mssql_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mssql_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mssql_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mssql_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mssql_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);

struct mssql_session
{
	int dbsecurity_rule_work;
	struct dbsecurity_rule_group *rule;
	struct evbuffer *buf;
};

struct mssql_session *mssql_session_new()
{
	struct mssql_session *session = SCMalloc(sizeof(struct mssql_session));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	session->buf = evbuffer_new();
	session->rule = NULL;
	session->dbsecurity_rule_work = 0;
	return session;
}

void mssql_session_free(struct mssql_session *session)
{
	evbuffer_free(session->buf);
	SCFree(session);
}

static void mssql_write_secauditlog(struct filter_header *hdr, int level, char *rule, char *content)
{
	char sip[20];
	char dip[20];
	char *user = NULL;
	char *proto = NULL;
	uint32_t *autoId = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	user = hdr->username ? hdr->username : "none";
	proto = (char*)server_strfromid(SVR_ID_MSSQL);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, hdr->tcp->source, hdr->tcp->dest, proto,
		user, "none", level, rule, "权限被拒绝", strlen(content), content);
}

void tvb_get_sql_m(uint8_t *input, const uint32_t input_len, const uint32_t offset, char *sql_str)
{
	uint8_t *ptr = NULL;
	ptr = fast_ensure_contiguous(input, input_len, offset, sizeof(uint32_t));
	memcpy(sql_str, (char*)ptr, 4 * sizeof(char));
}

static enum FLT_RET mssql_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SCLogInfo("MSSQL: on cli in, ssid: %d", hdr->sessionid);
	struct mssql_session *session = mssql_session_new();
	if (NULL == session)
	{
		return FLTRET_CLOSE;
	}
	hdr->user = session;
	return FLTRET_OK;
}

static enum FLT_RET mssql_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct mssql_session *session = hdr->user;
	struct acl_data *ad = hdr->private;
	int isok = *((int*)buff); assert(len == sizeof(isok));
	SCLogInfo("MSSQL: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

	if (CONNECT_FAILURE == isok)
		return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);

	if (NULL != ad && NULL != ad->group)
	{
		session->rule = ad->group->acl[SVR_ID_MSSQL].protocol_rule;
	}

	return FLTRET_OK;
}

static enum FLT_RET mssql_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SCLogInfo("MSSQL: on cli/svr len: %d, ssid: %d", (int)len, hdr->sessionid);
	struct mssql_session *session = hdr->user;
	uint8_t type = 0;
	uint16_t length = 0;
	char mssql_head[64] = { 0 };
	int access_allow = 0;

	/* check if dbsecurity rule work */
	if (NULL != session->rule)
	{
		if (0 != dbsecurity_check_rule_work_privilege(MSSQL, session->rule))
		{
			session->dbsecurity_rule_work = 1;
		}
	}

	if (evbuffer_add(session->buf, buff, len) != 0)
		return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);

	if (evbuffer_get_length(session->buf) < HEAD_LEN)
		return FLTRET_OK;

	if (evbuffer_copyout(session->buf, mssql_head, HEAD_LEN) != HEAD_LEN)
		return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);

	/* get the packet type */
	type = tvb_get_uint8((uint8_t*)mssql_head, HEAD_LEN, TYPE_OFFSET);

	/* Illegal packet types */
	if (!is_valid_tds_type(type))
	{
		mssql_write_secauditlog(hdr, l_critical, "packet type", "非法的数据包类型");
	}

	/* get the packet length */
	if (type == TDS_TLS_PKT)
	{
		length = tvb_get_ntohs((uint8_t *)mssql_head, HEAD_LEN, TLS_LENGTH_OFFSET);
		length += 5;
	}
	else
	{
		length = tvb_get_ntohs((uint8_t *)mssql_head, HEAD_LEN, LENGHT_OFFSET);
	}

	/* the length of received data is less than the analysed length */
	if (evbuffer_get_length(session->buf) < length)
		return FLTRET_OK;

	/* dbsecurity rule work */
	if (1 == session->dbsecurity_rule_work && hdr->svr != NULL)
	{
		/* check if in effective time */
		access_allow = dbsecurity_access_time_check(MSSQL, session->rule);
		if (access_allow != 0)
		{
			mssql_write_secauditlog(hdr, l_critical, "time control", "访问时间不在允许的访问时间段内");
			return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		/* check if valid db user */
		access_allow = dbsecurity_access_user_check(MSSQL, session->rule, NULL);
		if (access_allow != 0)
		{
			mssql_write_secauditlog(hdr, l_critical, "login user", "禁止访问的数据库用户");
			return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		/* check if valid sql */
		if (type == TDS_QUERY_PKT)
		{
			char tmp_pkt[128] = { 0 };
			evbuffer_copyout(session->buf, tmp_pkt, sizeof(tmp_pkt));
			char op_type[4] = { 0 };
			char sql_type[6] = { 0 };
			tvb_get_sql_m((uint8_t*)tmp_pkt, sizeof(tmp_pkt), QURE_PKT_OFFSET, sql_type);
			op_type[0] = sql_type[0];
			op_type[1] = sql_type[2];

			if (0 == strncasecmp(op_type, INSERT, 2 * sizeof(char)))
			{
				access_allow = dbsecurity_access_operation_check(MSSQL, session->rule, OP_INSERT);
				if (access_allow == 0)
				{
					mssql_write_secauditlog(hdr, l_critical, "sql", "数据库insert语句被禁止");
					return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
			}
			else if (0 == strncasecmp(op_type, SELECT, 2 * sizeof(char)))
			{
				access_allow = dbsecurity_access_operation_check(MSSQL, session->rule, OP_SELECT);
				if (access_allow == 0)
				{
					mssql_write_secauditlog(hdr, l_critical, "sql", "数据库select语句被禁止");
					return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
			}
			else if (0 == strncasecmp(op_type, DELETE, 2 * sizeof(char)))
			{
				access_allow = dbsecurity_access_operation_check(MSSQL, session->rule, OP_DELETE);
				if (access_allow == 0)
				{
					mssql_write_secauditlog(hdr, l_critical, "sql", "数据库delete语句被禁止");
					return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
			}
			else if (0 == strncasecmp(op_type, UPDATE, 2 * sizeof(char)))
			{
				access_allow = dbsecurity_access_operation_check(MSSQL, session->rule, OP_UPDATE);
				if (access_allow == 0)
				{
					mssql_write_secauditlog(hdr, l_critical, "sql", "数据库update语句被禁止");
					return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
			}
			else if (0 == strncasecmp(op_type, CREATE, 2 * sizeof(char)))
			{
				access_allow = dbsecurity_access_operation_check(MSSQL, session->rule, OP_CREATE);
				if (access_allow == 0)
				{
					mssql_write_secauditlog(hdr, l_critical, "sql", "数据库create语句被禁止");
					return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
			}
			else if (0 == strncasecmp(op_type, DROP, 2 * sizeof(char)))
			{
				access_allow = dbsecurity_access_operation_check(MSSQL, session->rule, OP_DROP);
				if (access_allow == 0)
				{
					mssql_write_secauditlog(hdr, l_critical, "sql", "数据库drop语句被禁止");
					return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
			}
			else
			{
			}
		}
	}

	if (evbuffer_sendtofwd(hdr, session->buf, length) != 0)
	{
		return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	if (evbuffer_get_length(session->buf) > 0)
	{
		SCLogInfo("MSSQL: session->buf has extra data len:%d\n", (int)evbuffer_get_length(session->buf));
		return mssql_onsockdata(hdr, FLTEV_ONSOCKDATA, NULL, 0);
	}

	return FLTRET_OK;
}

static enum FLT_RET mssql_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	const ForwardObject *obj = buff; assert(len == sizeof(obj));
	SCLogInfo("MSSQL: on fwd len:%d, ssid=%d", (int)obj->buffdata.len, hdr->sessionid);

	if (obj->cmd == FWDCMD_FORWARDDATA)
	{
		assert(obj->has_buffdata);
		int ret = buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len);
		if (ret != 0)
		{
			return mssql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
	}

	return FLTRET_OK;
}

static enum FLT_RET mssql_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct mssql_session *session = hdr->user;
	SCLogInfo("MSSQL: on socket close, ssid: %d", hdr->sessionid);
	mssql_session_free(session);
	hdr->user = NULL;
	return FLTRET_CLOSE;
}

enum FLT_RET mssql_oninit()
{
	g_mssql_ondata_cb[FLTEV_ONCLIIN] = mssql_oncliin;
	g_mssql_ondata_cb[FLTEV_ONSVROK] = mssql_svrok;
	g_mssql_ondata_cb[FLTEV_ONSOCKDATA] = mssql_onsockdata;
	g_mssql_ondata_cb[FLTEV_ONFWDDATA] = mssql_onfwddata;
	g_mssql_ondata_cb[FLTEV_ONSOCKERROR] = mssql_onsockerr;
	return FLTRET_OK;
}

enum FLT_RET mssql_onpkt(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	return g_mssql_ondata_cb[ev](hdr, ev, buff, len);
}

enum FLT_RET mssql_onfree()
{
	return FLTRET_OK;
}

enum SVR_ID mssql_check_data(const void *buff, size_t len)
{
	if (len > 2 && memcmp(buff, "\x12\x01", 2) == 0)
		return SVR_ID_MSSQL;
	return _SVR_ID_NONE;
}

static struct packet_filter g_filter_mssql = { SVR_ID_MSSQL, "mssql parser", mssql_oninit, mssql_onpkt, mssql_onfree, mssql_check_data };

PROTOCOL_FILTER_OP(mssql)


