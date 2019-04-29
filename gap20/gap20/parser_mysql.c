/* App Layer Parser for Mysql */
#include "app_common.h"
#include "parser_mysql.h"
#include "parser_tcp.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "nlkernel.h"
#include "parser_tcp.h"
#include "db_agent.h"
#include "gap_stgy.h"
#include "gap_cmd_dbsecurity.h"
#include "cmd_common.h"
#include "main_inouter.h"
#include "parser_orcl.h"
#include "parser_common.h"
#include "db_mysql.h"
#include "gap_cmd_group.h"


#define  MYSQL_REQUEST			0x00
#define  LOGIN_PACKET           0x01
#define  PACKET_NUMBER_OFFSET	3
#define  CMD_OFFSET             4
#define  SQL_OFFSET             5
#define  USER_NAME_OFFSET       36
#define  TRUE					1
#define  FALSE					0
#define  OFFSET_ERROR		    -1
#define  BoundsError			2
#define  OutLengthError			3
#define  MYSQL_HEAD_LEN			4
#define  MYSQL_CONTENT_LEN      128
#define  CONNECT_FAILURE        0
#define  IPV4_LEN               16
#define  OP_LEN                 4

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

#define  MYSQL          "MYSQL"
#define  CHECK_FLAG     "\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"

/* Packet Cmd */
enum MYSQL_CMD
{
	MYSQL_COM_SLEEP = 0x00,
	MYSQL_COM_QUIT,
	MYSQL_COM_INIT_DB,
	MYSQL_COM_QUERY,
	MYSQL_COM_FIELD_LIST,
	MYSQL_COM_CREATE_DB,
	MYSQL_COM_DROP_DB,
	MYSQL_COM_REFRESH,
	MYSQL_COM_SHUTDOWN,
	MYSQL_COM_STATISTICS,
	MYSQL_COM_PROCESS_INFO,
	MYSQL_COM_CONNECT,
	MYSQL_COM_PROCESS_KILL,
	MYSQL_COM_DEBUG,
	MYSQL_COM_PING,
	MYSQL_COM_TIME,
	MYSQL_COM_DELAYED_INSERT,
	MYSQL_COM_CHANGE_USER,
	MYSQL_COM_BINLOG_DUMP,
	MYSQL_COM_TABLE_DUMP,
	MYSQL_COM_CONNECT_OUT,
	MYSQL_COM_REGISTER_SLAVE,
	MYSQL_COM_STMT_PREPARE,
	MYSQL_COM_STMT_EXECUTE,
	MYSQL_COM_STMT_SEND_LONG_DATA,
	MYSQL_COM_STMT_CLOSE,
	MYSQL_COM_STMT_RESET,
	MYSQL_COM_SET_OPTION,
	MYSQL_COM_STMT_FETCH
};

#define pntoh32(p)  ((uint32_t)*((const uint8_t *)(p)+0)<<24|  \
                     (uint32_t)*((const uint8_t *)(p)+1)<<16|  \
                     (uint32_t)*((const uint8_t *)(p)+2)<<8|   \
                     (uint32_t)*((const uint8_t *)(p)+3)<<0)
#define pletoh24(p) ((uint32_t)*((const uint8_t *)(p)+2)<<16|  \
                     (uint32_t)*((const uint8_t *)(p)+1)<<8|   \
                     (uint32_t)*((const uint8_t *)(p)+0)<<0)

static FLT_ONPKTCB g_mysql_ondata_cb[FLTEV_COUNT] = { 0 };
static enum FLT_RET mysql_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mysql_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mysql_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mysql_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET mysql_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);

struct mysql_session
{
	int dbsecurity_rule_work;
	struct dbsecurity_rule_group *rule;
	struct evbuffer *buf;
};

struct mysql_session *mysql_session_new()
{
	struct mysql_session *session = SCMalloc(sizeof(struct mysql_session));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	session->buf = evbuffer_new();
	session->rule = NULL;
	session->dbsecurity_rule_work = 0;
	return session;
};

void mysql_session_free(struct mysql_session *session)
{
	evbuffer_free(session->buf);
	SCFree(session);
}

static void mysql_write_secauditlog(struct filter_header *hdr, int level, char *rule, char *content)
{
	char sip[20];
	char dip[20];
	char *user = NULL;
	char *proto = NULL;
	uint32_t *autoId = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	user = hdr->username ? hdr->username : "none";
	proto = (char*)server_strfromid(SVR_ID_MYSQL);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, hdr->tcp->source, hdr->tcp->dest, proto,
		user, "none", level, rule, "权限被拒绝", strlen(content), content);
}

uint32_t tvb_get_ntohl_pktlen(uint8_t *input, const uint32_t input_len, const uint32_t offset)
{
	uint8_t *ptr = NULL;
	ptr = fast_ensure_contiguous(input, input_len, offset, 3);
	return pletoh24(ptr);
}

void tvb_get_login_user(uint8_t *input, const uint32_t input_len, const uint32_t offset, char *name)
{
	uint8_t *ptr = NULL;
	char *name_ptr = name;
	int num = 0;
	ptr = fast_ensure_contiguous(input, input_len, offset, sizeof(uint32_t));

	while (*ptr != 0x00 && num < NAME_LEN)
	{
		memcpy(name_ptr + num, (char*)(ptr + num), sizeof(char));
		num++;
	}
}

void tvb_get_req_sql(uint8_t *input, const uint32_t input_len, const uint32_t offset, char *sql_str)
{
	uint8_t *ptr = NULL;
	ptr = fast_ensure_contiguous(input, input_len, offset, sizeof(uint32_t));
	memcpy(sql_str, (char*)ptr, 2 * sizeof(char));
}

static enum FLT_RET mysql_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SCLogInfo("mysql: on client in, dstport: %d, ssid: %d", ntohs(hdr->tcp->dest), hdr->sessionid);
	struct mysql_session *session = mysql_session_new();
	if (NULL == session)
	{
		return FLTRET_CLOSE;
	}
	hdr->user = session;
	return FLTRET_OK;
}

static enum FLT_RET mysql_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct mysql_session *session = hdr->user;
	struct acl_data *ad = hdr->private;
	int isok = *((int*)buff);
	assert(len == sizeof(isok));
	SCLogInfo("mysql: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

	if (CONNECT_FAILURE == isok)
	{
		return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	if (NULL != ad && NULL != ad->group)
	{
		session->rule = ad->group->acl[SVR_ID_MYSQL].protocol_rule;
	}

	return FLTRET_OK;
}

static enum FLT_RET mysql_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct mysql_session *session = hdr->user;
	uint8_t sequence_number = 0;
	uint32_t pkt_len_offset = 0;
	uint32_t pkt_len = 0;
	char mysql_head[MYSQL_HEAD_LEN] = { 0 };
	char pkt_content[MYSQL_CONTENT_LEN] = { 0 };
	int access_allow = 0;
	char user_name[NAME_LEN] = { 0 };
	char op_type[OP_LEN] = { 0 };
	SCLogInfo("MYSQL: on cli/svr len: %d, ssid: %d", (int)len, hdr->sessionid);

	/* check if dbsecurity rule work */
	if (NULL != session->rule)
	{
		if (0 != dbsecurity_check_rule_work_privilege(MYSQL, session->rule))
		{
			session->dbsecurity_rule_work = 1;
		}
	}

	if (evbuffer_add(session->buf, buff, len) != 0)
	{
		return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	if (evbuffer_get_length(session->buf) < MYSQL_HEAD_LEN)
		return FLTRET_OK;

	if (evbuffer_copyout(session->buf, mysql_head, MYSQL_HEAD_LEN) != MYSQL_HEAD_LEN)
		return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);

	pkt_len = tvb_get_ntohl_pktlen((uint8_t*)mysql_head, MYSQL_HEAD_LEN, pkt_len_offset);

	if (evbuffer_get_length(session->buf) < pkt_len + MYSQL_HEAD_LEN)
		return FLTRET_OK;

	sequence_number = tvb_get_uint8((uint8_t *)mysql_head, MYSQL_HEAD_LEN, PACKET_NUMBER_OFFSET);

	evbuffer_copyout(session->buf, pkt_content, sizeof(pkt_content));
	uint8_t cmd = tvb_get_uint8((uint8_t *)pkt_content, sizeof(pkt_content), CMD_OFFSET);

	if ((1 == session->dbsecurity_rule_work) && (NULL != hdr->svr))
	{
		/* check if in effective time */
		access_allow = dbsecurity_access_time_check(MYSQL, session->rule);
		if (access_allow != 0)
		{
			mysql_write_secauditlog(hdr, l_critical, "time control", "访问时间不在允许的访问时间段内");
			return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		if (sequence_number == LOGIN_PACKET)
		{
			/* get login user */
			tvb_get_login_user((uint8_t*)pkt_content, sizeof(pkt_content), USER_NAME_OFFSET, user_name);
			/* check if valid user */
			access_allow = dbsecurity_access_user_check(MYSQL, session->rule, user_name);
			if (access_allow != 0)
			{
				mysql_write_secauditlog(hdr, l_critical, "login user", "禁止访问的数据库用户");
				return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
		}
		else
		{
			if (cmd == MYSQL_COM_QUERY)
			{
				tvb_get_req_sql((uint8_t*)pkt_content, sizeof(pkt_content), SQL_OFFSET, op_type);

				if (0 == strncasecmp(op_type, INSERT, 2 * sizeof(char)))
				{
					access_allow = dbsecurity_access_operation_check(MYSQL, session->rule, OP_INSERT);
					if (0 == access_allow)
					{
						mysql_write_secauditlog(hdr, l_critical, "sql", "数据库insert语句被禁止");
						return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
				}
				else if (0 == strncasecmp(op_type, SELECT, 2 * sizeof(char)))
				{

					access_allow = dbsecurity_access_operation_check(MYSQL, session->rule, OP_SELECT);
					if (0 == access_allow)
					{
						mysql_write_secauditlog(hdr, l_critical, "sql", "数据库select语句被禁止");
						return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
				}
				else if (0 == strncasecmp(op_type, DELETE, 2 * sizeof(char)))
				{
					access_allow = dbsecurity_access_operation_check(MYSQL, session->rule, OP_DELETE);
					if (0 == access_allow)
					{
						mysql_write_secauditlog(hdr, l_critical, "sql", "数据库delete语句被禁止");
						return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
				}
				else if (0 == strncasecmp(op_type, UPDATE, 2 * sizeof(char)))
				{
					access_allow = dbsecurity_access_operation_check(MYSQL, session->rule, OP_UPDATE);
					if (0 == access_allow)
					{
						mysql_write_secauditlog(hdr, l_critical, "sql", "数据库update语句被禁止");
						return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
				}
				else if (0 == strncasecmp(op_type, CREATE, 2 * sizeof(char)))
				{
					access_allow = dbsecurity_access_operation_check(MYSQL, session->rule, OP_CREATE);
					if (0 == access_allow)
					{
						mysql_write_secauditlog(hdr, l_critical, "sql", "数据库create语句被禁止");
						return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
				}
				else if (0 == strncasecmp(op_type, DROP, 2 * sizeof(char)))
				{
					access_allow = dbsecurity_access_operation_check(MYSQL, session->rule, OP_DROP);
					if (0 == access_allow)
					{
						mysql_write_secauditlog(hdr, l_critical, "sql", "数据库drop语句被禁止");
						return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
				}
				else
				{
				}
			}
		}
	}

	if (evbuffer_sendtofwd(hdr, session->buf, pkt_len + 4) != 0)
	{
		char *err = "evbuffer_sendtofwd failure";
		return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	if (evbuffer_get_length(session->buf) > 0)
	{
		SCLogInfo("--------------MYSQL: session->buf has extra data len:%d\n", (int)evbuffer_get_length(session->buf));
		return mysql_onsockdata(hdr, FLTEV_ONSOCKDATA, NULL, 0);
	}

	return FLTRET_OK;
}

static enum FLT_RET mysql_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	const ForwardObject *obj = buff;
	assert(len == sizeof(obj));
	SCLogInfo("MYSQL: on fwd len:%d, ssid=%d", (int)obj->buffdata.len, hdr->sessionid);

	if (obj->cmd == FWDCMD_FORWARDDATA)
	{
		assert(obj->has_buffdata);
		int ret = buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len);
		if (ret != 0)
		{
			char *err = "buffer_sendtoreq failure";
			return mysql_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
	}

	return FLTRET_OK;
}

static enum FLT_RET mysql_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct mysql_session *session = hdr->user;
	SCLogInfo("MYSQL: on socket close, ssid: %d", hdr->sessionid);
	mysql_session_free(session);
	hdr->user = NULL;
	return FLTRET_CLOSE;
}

enum FLT_RET mysql_oninit()
{
	g_mysql_ondata_cb[FLTEV_ONCLIIN] = mysql_oncliin;
	g_mysql_ondata_cb[FLTEV_ONSVROK] = mysql_svrok;
	g_mysql_ondata_cb[FLTEV_ONSOCKDATA] = mysql_onsockdata;
	g_mysql_ondata_cb[FLTEV_ONFWDDATA] = mysql_onfwddata;
	g_mysql_ondata_cb[FLTEV_ONSOCKERROR] = mysql_onsockerr;
	return FLTRET_OK;
}

enum FLT_RET mysql_onpkt(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	return g_mysql_ondata_cb[ev](hdr, ev, buff, len);
}

enum FLT_RET mysql_onfree()
{
	return FLTRET_OK;
}

enum SVR_ID mysql_check_data(const void *buff, size_t len)
{
	if (NULL != memnmem(buff, len, CHECK_FLAG, strlen(CHECK_FLAG)))
		return SVR_ID_MYSQL;
	return _SVR_ID_NONE;
}

static struct packet_filter g_filter_mysql = { SVR_ID_MYSQL, "mysql parser", mysql_oninit, mysql_onpkt, mysql_onfree, mysql_check_data };

PROTOCOL_FILTER_OP(mysql)