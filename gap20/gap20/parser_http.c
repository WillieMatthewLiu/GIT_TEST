#include "app_common.h"
#include "parser_tcp.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include <htp/htp.h>
#include "gapconfig.h"
#include "db_agent.h"
#include "parser_http.h"
#include "gap_cmd_http.h"
#include "gap_stgy.h"
#include "cmd_common.h"
#include "main_inouter.h"
#include "parser_common.h"
#include "db_mysql.h"
#include "gap_cmd_group.h"
#include "gap_ctl.h"

#define HOOK_OK 0
#define HOOK_ERROR -1
#define CONNECT_FAILURE 0
#define TRUE 1
#define RET_FALSE -1
#define RET_TRUE 0
#define IPV4_LEN 16
#define ERROR_LEN 512
#define ERROR_CONTENT_LEN 128
#define HOST_LEN 1024
#define TYPE_LEN 1024
#define HOST "Host:"
#define LOCATION "Location:"
#define CONTENT_TYPE "Content-Type:"
#define CONTENT_LEN "Content-Length:"
#define RESP_ERROR "HTTP/1.1 200 ok\r\nContent-Length:%d\r\n\r\n%s"
#define RESP_CONTENT_ERROR "<html><script>alert(\"%s\");window.close();</script></html>"
#define CHARSET "charset:"

#define RQST_URL_ERROR "URL permission denied"
#define RQST_METHOD_ERROR "method permission denied"
#define RQST_MIME_ERROR "mime permission denied"
#define RQST_HEAD_LEN_ERROR "exceed head length"
#define RQST_HEAD_ERROR "request head denied"
#define RESP_SCRIPT_ERROR "script permission denied"
#define RESP_KEYWORD_ERROR "keyword permission denied"
#define RESP_TIME_CONTROL_ERROR "effective time access denied"
#define RESP_USER_NUM_ERROR "exceed max user number"
#define RESP_FILE_LEN "exceed file length"
#define RESP_FILE_TYPE "file type permission denied"

#define HTTP_GET "GET /"
#define HTTP_POST "POST /"
#define HTTP_HEAD "HEAD /"
#define HTTP_TRACE "TRACE /"
#define HTTP_PUT "PUT /"
#define HTTP_OPTIONS "OPTIONS /"
#define HTTP_DELETE "DELETE /" 
#define HTTP_CONNECT "CONNECT /"


htp_cfg_t *cfg = NULL;
static FLT_ONPKTCB g_http_ondata_cb[FLTEV_COUNT] = { 0 };
static enum FLT_RET http_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET http_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET http_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET http_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
static enum FLT_RET http_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
enum FLT_RET http_head_func(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
enum FLT_RET http_content_func(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);

char *download_file_type[] = {
	"application/octet-stream",
	"application/x-msdownload",
	"application/x-zip-compressed",
	"application/msword",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.visio",
	"text/plain"
};

#define DOWNLOAD_FILE_TYPE_MAX (sizeof(download_file_type) / sizeof(download_file_type[0]))

struct http_session* http_session_new()
{
	struct http_session *session = SCMalloc(sizeof(struct http_session));
	if (session == NULL)
		return NULL;
	session->buf = evbuffer_new();
	session->buf_head = evbuffer_new();
	session->buf_tmp = evbuffer_new();
	session->conn = htp_connp_create(cfg);
	session->rule = NULL;
	session->last_file_data = NULL;
	session->url_file_type = NULL;
	session->http_state_func = NULL;
	session->head.method = NULL;
	session->head.url = NULL;
	session->head.mime = NULL;
	session->head.charset = NULL;
	session->head.file_name = NULL;
	session->head.virus_detection_file_path = NULL;
	session->head.virus_detection_file = NULL;
	session->head.flag_download_file = 0;
	session->head.content_len = 0;
	session->head.head_len = 0;
	session->head.virus_detection = 0;
	session->head.flag_virus = 0;
	session->head.remain_bytes_cnt = 0;
	session->head.user_num = 0;
	session->http_rule_work = 0;
	memset(session->url_file_name, 0, sizeof(session->url_file_name));
	return session;
}

void http_session_free(struct http_session *session)
{
	evbuffer_free(session->buf);
	evbuffer_free(session->buf_head);
	evbuffer_free(session->buf_tmp);
	htp_connp_destroy_all(session->conn);
	if (NULL != session->head.method)
	{
		SCFree(session->head.method);
	}
	if (NULL != session->head.mime)
	{
		SCFree(session->head.mime);
	}
	if (NULL != session->head.url)
	{
		SCFree(session->head.url);
	}
	if (NULL != session->head.charset)
	{
		SCFree(session->head.charset);
	}
	if (NULL != session->head.file_name)
	{
		SCFree(session->head.file_name);
	}
	if (NULL != session->head.virus_detection_file_path)
	{
		SCFree(session->head.virus_detection_file_path);
	}
	if (NULL != session->last_file_data)
	{
		SCFree(session->last_file_data);
	}
	SCFree(session);
}

int callback_request_line(htp_tx_t *tx)
{
	/* judge the first line of http protocal validity */
	if ((tx->request_method_number == HTP_M_UNKNOWN) || (tx->request_protocol_number) < 0 || tx->is_protocol_0_9 == 1)
	{
		return HOOK_ERROR;
	}
	return HOOK_OK;
}

int callback_request_headers(htp_tx_t *tx)
{
	htp_header_t *header = (htp_header_t *)htp_table_get_c(tx->request_headers, "");
	if (header != NULL)
	{
		return HOOK_ERROR;
	}
	return HOOK_OK;
}

int callback_request_body_data(htp_tx_data_t *d)
{
	return HOOK_OK;
}

int callback_request_trailer(htp_tx_t *tx)
{
	return HOOK_OK;
}

int callback_response_line(htp_tx_t *tx)
{
	/* judge the first line of http protocal validity */
	if ((tx->response_status_number < 0) || (tx->response_protocol_number < 0))
	{
		return HOOK_ERROR;
	}
	return HOOK_OK;
}

int callback_response_headers(htp_tx_t *tx)
{
	htp_header_t *header = (htp_header_t *)htp_table_get_c(tx->response_headers, "");
	if (header != NULL)
	{
		return HOOK_ERROR;
	}
	return HOOK_OK;
}

int callback_response_body_data(htp_tx_data_t *d)
{
	return HOOK_OK;
}

int callback_response_trailer(htp_tx_t *tx)
{
	return HOOK_OK;
}

static void http_write_secauditlog(struct filter_header *hdr, int level, char *rule, char *content)
{
	char sip[20];
	char dip[20];
	char *user = NULL;
	char *proto = NULL;
	uint32_t *autoId = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	user = hdr->username ? hdr->username : "none";
	proto = (char*)server_strfromid(SVR_ID_HTTP);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, hdr->tcp->source, hdr->tcp->dest, proto,
		user, "none", level, rule, "权限被拒绝", strlen(content), content);
}

static int check_download_file(const char *line)
{
	int ret = 0;
	int i = 0;

	for (i = 0; i < DOWNLOAD_FILE_TYPE_MAX; i++)
	{
		if (NULL != strcasestr(line, download_file_type[i]))
		{
			ret = 1;
			break;
		}
	}
	return ret;
}

static int http_rqst_err(struct filter_header *hdr, const char *buff)
{
	char resp_err_str[ERROR_LEN] = { 0 };
	char resp_content_str[ERROR_CONTENT_LEN] = { 0 };

	snprintf(resp_content_str, ERROR_CONTENT_LEN, RESP_CONTENT_ERROR, buff);
	snprintf(resp_err_str, ERROR_LEN, RESP_ERROR, strlen(resp_content_str), resp_content_str);
	buffer_sendtoreq(hdr, resp_err_str, strlen(resp_err_str));
}

static int replace_rqst_host(struct filter_header *hdr)
{
	struct http_session *session = hdr->user;
	char *line = NULL;
	char ip[IPV4_LEN] = { 0 };
	char host[HOST_LEN] = { 0 };
	addr2str(hdr->ip->daddr, ip);
	sprintf(host, "Host: %s\r\n", ip);

	while (1)
	{
		if ((line = evbuffer_readln(session->buf, NULL, EVBUFFER_EOL_CRLF_STRICT)) == NULL)
		{
			return RET_FALSE;
		}

		if (line[0] == '\0')
		{
			SCFree(line);
			break;
		}

		if (strncasecmp(line, HOST, strlen(HOST)) == 0)
		{
			SCFree(line);
			continue;
		}

		if (0 != evbuffer_add(session->buf_head, line, strlen(line)))
		{
			SCFree(line);
			return RET_FALSE;
		}

		if (0 != evbuffer_add(session->buf_head, "\r\n", 2))
		{
			SCFree(line);
			return RET_FALSE;
		}
		SCFree(line);
	}
	/* finally, store in session->buf_head */
	if (0 != evbuffer_add(session->buf_head, host, strlen(host)))
		return RET_FALSE;
	if (0 != evbuffer_add(session->buf_head, "\r\n", 2))
		return RET_FALSE;

	return RET_TRUE;
}

static int replace_resp_location(struct filter_header *hdr)
{
	struct http_session *session = hdr->user;
	char *line = NULL;
	char *lct_start = NULL;
	char location[HOST_LEN] = { 0 };
	int flag = FALSE;

	while (1)
	{
		if ((line = evbuffer_readln(session->buf, NULL, EVBUFFER_EOL_CRLF_STRICT)) == NULL)
		{
			return RET_FALSE;
		}

		if (line[0] == '\0')
		{
			SCFree(line);
			break;
		}

		/* change location info */
		if (strncasecmp(line, LOCATION, strlen(LOCATION)) == 0)
		{
			lct_start = strrchr(line, '/');
			if (lct_start != NULL)
			{
				sprintf(location, "Location: http://%s%s\r\n", session->extra, lct_start);
			}

			flag = TRUE;
			SCFree(line);
			continue;
		}

		if (0 != evbuffer_add(session->buf_head, line, strlen(line)))
		{
			SCFree(line);
			return RET_FALSE;
		}

		if (0 != evbuffer_add(session->buf_head, "\r\n", 2))
		{
			SCFree(line);
			return RET_FALSE;
		}
		SCFree(line);
	}

	/* finally, store in session->buf_head */
	if (flag == TRUE)
	{
		if (0 != evbuffer_add(session->buf_head, location, strlen(location)))
			return RET_FALSE;
	}

	if (0 != evbuffer_add(session->buf_head, "\r\n", 2))
		return RET_FALSE;

	return RET_TRUE;
}

static int get_rqst_head_args(struct filter_header *hdr, struct http_filter *head)
{
	struct http_session *session = hdr->user;
	size_t read_out;
	char *tmp = NULL;
	char *line = NULL;
	char *p = NULL;
	char *file_name = NULL;

	if ((line = evbuffer_readln(session->buf_head, &read_out, EVBUFFER_EOL_CRLF_STRICT)) == NULL)
	{
		return RET_FALSE;
	}

	/* get method */
	p = strchr(line, ' ');
	if (p == NULL || *p != ' ')
	{
		SCFree(line);
		return RET_FALSE;
	}

	if (head->method != NULL)
	{
		SCFree(head->method);
		head->method = NULL;
	}
	head->method = SCMalloc(p - line + 1);
	memcpy(head->method, line, p - line);
	head->method[p - line] = '\0';
	tmp = p + 1; p = strchr(tmp, ' ');
	if (p == NULL || *p != ' ')
	{
		SCFree(line);
		return RET_FALSE;
	}

	/* get url */
	if (head->url != NULL)
	{
		SCFree(head->url);
		head->url = NULL;
	}
	head->url = SCMalloc(p - tmp + 1);
	memcpy(head->url, tmp, p - tmp);
	head->url[p - tmp] = '\0';
	urldecode(head->url);

	/* get file-name */
	if (head->file_name != NULL)
	{
		SCFree(head->file_name);
		head->file_name = NULL;
	}
	file_name = strrchr(head->url, '/');
	if (NULL != file_name)
	{
		file_name++;
		head->file_name = SCStrdup(file_name);
	}

	if (0 != evbuffer_add(session->buf_tmp, line, read_out))
	{
		SCFree(line);
		return RET_FALSE;
	}
	if (0 != evbuffer_add(session->buf_tmp, "\r\n", 2))
	{
		SCFree(line);
		return RET_FALSE;
	}
	SCFree(line);

	if (0 != evbuffer_add_buffer(session->buf_tmp, session->buf_head))
	{
		return RET_FALSE;
	}
	if (0 != evbuffer_add_buffer(session->buf_head, session->buf_tmp))
	{
		return RET_FALSE;
	}
	return RET_TRUE;
}

static int get_resp_head_args(struct filter_header *hdr, struct http_filter *head)
{
	struct http_session *session = hdr->user;
	char *line = NULL;
	size_t read_out;
	char *mime_start = NULL;
	char *mime_end = NULL;
	char *charset_start = NULL;
	char *charset_end = NULL;
	char *len_start = NULL;

	while (1)
	{
		if ((line = evbuffer_readln(session->buf_head, &read_out, EVBUFFER_EOL_CRLF_STRICT)) == NULL)
		{
			return RET_FALSE;
		}

		if (line[0] == '\0')
		{
			SCFree(line);
			break;
		}

		/* get MIME type */
		if (strncasecmp(line, CONTENT_TYPE, strlen(CONTENT_TYPE)) == 0)
		{
			if (1 == check_download_file(line))
			{
				head->flag_download_file = 1;
			}

			mime_start = strchr(line, ':');
			mime_end = strchr(line, '/');
			if (NULL != head->mime)
			{
				SCFree(head->mime);
				head->mime = NULL;
			}
			head->mime = SCMalloc(mime_end - mime_start + 1);
			if (mime_start != NULL && mime_end != NULL)
			{
				mime_start++;
				while (*mime_start == ' ')
				{
					mime_start++;
				}
				memcpy(head->mime, mime_start, mime_end - mime_start);
				head->mime[mime_end - mime_start] = '\0';
			}

			charset_start = strstr(line, CHARSET);
			charset_end = line + read_out;
			if (NULL != charset_start)
			{
				if (NULL != head->charset)
				{
					SCFree(head->charset);
					head->charset = NULL;
				}
				head->mime = SCMalloc(charset_end - charset_start + 1);

				charset_start++;
				while (*charset_start == ' ')
				{
					charset_start++;
				}
				memcpy(head->charset, charset_start, charset_end - charset_start);
				head->charset[charset_end - charset_start] = '\0';
			}
		}

		/* get Content-Length */
		if (strncasecmp(line, CONTENT_LEN, strlen(CONTENT_LEN)) == 0)
		{
			len_start = strchr(line, ':');
			if (NULL != len_start)
			{
				len_start++;
				while (*len_start == ' ')
				{
					len_start++;
				}
				head->content_len = atoi(len_start);
			}
		}

		if (0 != evbuffer_add(session->buf_tmp, line, strlen(line)))
		{
			SCFree(line);
			return RET_FALSE;
		}

		if (0 != evbuffer_add(session->buf_tmp, "\r\n", 2))
		{
			SCFree(line);
			return RET_FALSE;
		}
		SCFree(line);
	}

	if (0 != evbuffer_add(session->buf_tmp, "\r\n", 2))
	{
		return RET_FALSE;
	}
	if (0 != evbuffer_add_buffer(session->buf_head, session->buf_tmp))
	{
		return RET_FALSE;
	}
	return RET_TRUE;
}


static int security_check(struct filter_header *hdr, const void *buff, size_t len)
{
	int ret = 0;
	struct http_session *session = hdr->user;

	if (hdr->svr != NULL)
	{
		ret = htp_connp_req_data(session->conn, NULL, buff, len);
	}
	else
	{
		htp_connp_req_data(session->conn, NULL, buff, len);
		ret = htp_connp_res_data(session->conn, NULL, buff, len);
	}

	return ret;
}

void *thread_virus_detection(void *args)
{
	struct filter_header *hdr = (struct filter_header *)args;
	struct http_session *session = hdr->user;

	/* virus detection */
	if (0 == http_file_virus_detection(session->head.virus_detection_file_path))
	{
		buffer_sendtoreq(hdr, session->last_file_data, session->last_file_len);
	}
	else
	{
		http_write_secauditlog(hdr, l_critical, "virus detection", session->head.virus_detection_file_path);
	}
	SCLogInfo("rm temp file %s\n", session->head.virus_detection_file_path);
	cmd_system_novty_arg("rm -rf %s", session->head.virus_detection_file_path);
	SCFree(session->head.virus_detection_file_path);
	session->head.virus_detection_file_path = NULL;
	session->head.virus_detection_file = NULL;
	session->head.remain_bytes_cnt = 0;
	session->head.virus_detection = 0;
	sessionmap_postclose_byhdr(hdr);
	return NULL;
}

static enum FLT_RET http_oncliin(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SCLogInfo("http: on client in, dstport: %d, ssid: %d", ntohs(hdr->tcp->dest), hdr->sessionid);
	struct http_session *session = http_session_new();
	if (session == NULL)
	{
		return FLTRET_CLOSE;
	}
	hdr->user = session;

	if (hdr->svr != NULL)
	{
		tlvbox_put_string_fmt(hdr->tlv_out, TLV_HTTP_EXTRA, "%s:%d", hdr->svr->localip, hdr->svr->localport);
	}
	else
	{
		if (hdr->tlv_in != NULL)
		{
			strncpy(session->extra, tlv_get_string(tlvbox_find(hdr->tlv_in, TLV_HTTP_EXTRA)), sizeof(session->extra));
		}
	}
	return FLTRET_OK;
}

static enum FLT_RET http_svrok(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct http_session *session = hdr->user;
	struct acl_data *ad = hdr->private;
	int isok = *((int*)buff);
	assert(len == sizeof(isok));
	SCLogInfo("http: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

	if (isok == CONNECT_FAILURE)
	{
		return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	if (NULL != ad)
	{
		if (NULL != ad->group)
		{
			SCLogInfo("http: ad->group: %p\n", ad->group);
			session->rule = ad->group->acl[SVR_ID_HTTP].protocol_rule;
		}
		if (NULL != ad->user)
		{
			session->head.user_num = get_session_by_user(ad->user, "HTTP");
		}
	}

	/* check if http rule work */
	if (NULL != session->rule)
	{
		if (0 != http_check_rule_work_privilege(session->rule))
		{
			session->http_rule_work = 1;
			tlvbox_put_uint32(hdr->tlv_out, TLV_HTTP_RULE_WORK, session->http_rule_work);
		}
	}
	/* check if in effective time */
	if ((1 == session->http_rule_work) && (0 != http_check_effectime(session->rule)))
	{
		http_rqst_err(hdr, RESP_TIME_CONTROL_ERROR);
		http_write_secauditlog(hdr, l_critical, "time control", "访问时间不在允许的访问时间段内");
		return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}
	/* check if valid user connection num */
	if ((1 == session->http_rule_work) && (0 != http_check_user_num(hdr, session->rule, &session->head)))
	{
		http_rqst_err(hdr, RESP_USER_NUM_ERROR);
		http_write_secauditlog(hdr, l_critical, "user connetion contorl", "连接数据超过允许的最大用户连接数");
		return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	session->http_state_func = http_head_func;
	return FLTRET_OK;
}

enum FLT_RET http_head_func(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct http_session *session = hdr->user;
	char *check_head = NULL;
	char *check_content = NULL;

	if (0 != evbuffer_add(session->buf, buff, len))
	{
		return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	/* received the whole request header or response header */
	struct evbuffer_ptr pos;
	pos = evbuffer_search(session->buf, "\r\n\r\n", 4, NULL);
	if (pos.pos == -1)
	{
		return FLTRET_OK;
	}
	session->head.head_len = pos.pos + 4;

	/* security check for http request and response head */
	check_head = SCMalloc(session->head.head_len);
	evbuffer_copyout(session->buf, check_head, session->head.head_len);
	if (security_check(hdr, check_head, session->head.head_len) == 3)
	{
		http_write_secauditlog(hdr, l_critical, "http format check", "http头部数据格式不正确");
		SCFree(check_head);
		return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}
	SCFree(check_head);

	/* http head parser */
	if (hdr->svr != NULL)
	{
		if (0 != replace_rqst_host(hdr))
		{
			return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		/* http rule work */
		if (1 == session->http_rule_work)
		{
			/* get request args */
			if (0 != get_rqst_head_args(hdr, &session->head))
			{
				return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
			}

			/* put file name of url into tlv */
			if (NULL != session->head.file_name)
			{
				tlvbox_put_string_fmt(hdr->tlv_out, TLV_HTTP_FILE_NAME, "%s", session->head.file_name);
			}
			/* check http head method, url, head_len */
			if (0 != http_check_rqst_head_privilege(hdr, session->rule, &session->head))
			{
				http_rqst_err(hdr, RQST_HEAD_ERROR);
				http_write_secauditlog(hdr, l_critical, "http head filter", "禁止http请求头方法");
				return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
		}
	}
	else
	{
		if (0 != replace_resp_location(hdr))
		{
			return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
		/* http rule work */
		if (1 == session->http_rule_work)
		{
			/* get response args */
			if (0 != get_resp_head_args(hdr, &session->head))
			{
				return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
			/* check http head mime, head_len */
			if (0 != http_check_resp_head_privilege(hdr, session->rule, &session->head))
			{
				http_write_secauditlog(hdr, l_critical, "http head filter", "禁止的http应答头方法");
				return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
			session->head.remain_bytes_cnt = evbuffer_get_length(session->buf);

			/* check if download file */
			if (1 == session->head.flag_download_file)
			{
				/* check download file privilege */
				if (0 != http_check_file_privilege(session->rule))
				{
					http_write_secauditlog(hdr, l_critical, "file download privilege", "禁止http文件下载");
					return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
				/* check file type */
				if (0 != http_check_file_type_privilege(hdr, session->rule, session->url_file_type))
				{
					http_write_secauditlog(hdr, l_critical, "file download type", "禁止下载的文件类型");
					return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
				/* check file length */
				if (0 != http_check_file_length_privilege(hdr, session->rule, &session->head))
				{
					http_write_secauditlog(hdr, l_critical, "file download size", "超过允许下载文件大小限制");
					return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
				}
				/* check if need virus detection */
				if (0 != http_check_file_virus_detection(session->rule))
				{
					session->head.virus_detection = 1;
					tlvbox_put_uint32(hdr->tlv_out, TLV_HTTP_VIRUS_DETECTION, session->head.virus_detection);
					tlvbox_put_uint64(hdr->tlv_out, TLV_HTTP_CONTENT_LENGTH, session->head.content_len);
					tlvbox_put_uint64(hdr->tlv_out, TLV_HTTP_HEAD_LEN, session->head.head_len);
				}
				/* send head and data separately */
				if (1 == session->head.virus_detection)
				{
					/* send head buff */
					if (0 != evbuffer_sendtofwd(hdr, session->buf_head, 0))
					{
						return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
					/* check if follow with data */
					if (session->head.remain_bytes_cnt > 0)
					{
						/* send data buff */
						if (0 != evbuffer_sendtofwd(hdr, session->buf, 0))
						{
							return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
						}
					}
					session->http_state_func = http_content_func;
					return FLTRET_OK;
				}
			}
			else
			{
				if (session->head.remain_bytes_cnt > 0)
				{
					check_content = SCMalloc(session->head.remain_bytes_cnt);
					evbuffer_copyout(session->buf, check_content, session->head.remain_bytes_cnt);
					/* check http content keyword, script */
					if (0 != http_check_content_privilege(session->rule, check_content, session->head.charset))
					{
						http_write_secauditlog(hdr, l_critical, "http content filter", "禁止的http协议内容关键字");
						SCFree(check_content);
						return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
					SCFree(check_content);
				}
			}
		}
	}

	evbuffer_add_buffer(session->buf_head, session->buf);
	if (0 != evbuffer_sendtofwd(hdr, session->buf_head, 0))
	{
		return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}

	session->http_state_func = http_content_func;
	return FLTRET_OK;
}

enum FLT_RET http_content_func(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct http_session *session = hdr->user;

	if (1 == session->http_rule_work)
	{
		if (NULL == hdr->svr && 0 == session->head.flag_download_file)
		{
			/* check http content keyword, script */
			if (0 != http_check_content_privilege(session->rule, buff, session->head.charset))
			{
				http_write_secauditlog(hdr, l_critical, "http content filter", "禁止的http协议内容关键字");
				return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
		}
	}

	/* send data buff */
	if (0 != buffer_sendtofwd(hdr, buff, len))
	{
		return http_onsockerr(hdr, FLTEV_ONSOCKERROR, buff, len);
	}
	return FLTRET_OK;
}

static enum FLT_RET http_onsockdata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	SCLogInfo("http: on sock data,len:%d, ssid: %d", len, hdr->sessionid);
	struct http_session *session = hdr->user;
	return session->http_state_func(hdr, ev, buff, len);
}

static enum FLT_RET http_onfwddata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct http_session *session = hdr->user;
	const ForwardObject *obj = buff;
	struct tlvhdr *hdr_url_name = NULL;
	struct tlvhdr *hdr_virus_detection = NULL;
	struct tlvhdr *hdr_content_length = NULL;
	struct tlvhdr *hdr_head_length = NULL;
	struct tlvhdr *hdr_http_rule_work = NULL;
	char filename[FILE_NAME_LEN] = { 0 };
	pthread_t pthread;
	assert(len == sizeof(obj));

	if (obj->cmd == FWDCMD_FORWARDDATA)
	{
		SCLogInfo("http: on fwd data,len:%d, ssid: %d", (int)obj->buffdata.len, hdr->sessionid);
		assert(obj->has_buffdata);
		session->http_state_func = http_head_func;

		hdr_http_rule_work = tlvbox_find(hdr->tlv_in, TLV_HTTP_RULE_WORK);
		if (NULL != hdr_http_rule_work)
		{
			session->http_rule_work = tlv_get_uint32(hdr_http_rule_work);
		}

		if (1 == session->http_rule_work)
		{
			if (hdr->svr == NULL)
			{
				hdr_url_name = tlvbox_find(hdr->tlv_in, TLV_HTTP_FILE_NAME);
				if (NULL != hdr_url_name)
				{
					strncpy(session->url_file_name, tlv_get_string(hdr_url_name), sizeof(session->url_file_name));
					session->url_file_type = strchr(session->url_file_name, '.');
				}
			}
			else
			{
				/* check if need virus */
				if (0 == session->head.virus_detection)
				{
					hdr_virus_detection = tlvbox_find(hdr->tlv_in, TLV_HTTP_VIRUS_DETECTION);
					if (NULL != hdr_virus_detection)
					{
						session->head.virus_detection = tlv_get_uint32(hdr_virus_detection);
					}
					hdr_content_length = tlvbox_find(hdr->tlv_in, TLV_HTTP_CONTENT_LENGTH);
					if (NULL != hdr_content_length)
					{
						session->head.content_len = tlv_get_uint64(hdr_content_length);
					}
					hdr_head_length = tlvbox_find(hdr->tlv_in, TLV_HTTP_HEAD_LEN);
					if (NULL != hdr_head_length)
					{
						session->head.head_len = tlv_get_uint64(hdr_head_length);
					}
				}
				/* cache vitus detection file */
				if (1 == session->head.virus_detection && obj->buffdata.len != session->head.head_len)
				{
					session->head.remain_bytes_cnt += obj->buffdata.len;

					if (NULL == session->head.virus_detection_file)
					{
						snprintf(filename, sizeof(filename), "%s%d", HTTP_VIRUS_DETECTION_FILE_PRE, hdr->sessionid);
						session->head.virus_detection_file_path = SCStrdup(filename);
						if (NULL == session->head.virus_detection_file_path)
						{
							return http_onsockerr(hdr, FLTEV_ONSOCKERROR, obj->buffdata.data, obj->buffdata.len);
						}
						session->head.virus_detection_file = fopen(session->head.virus_detection_file_path, "w+");
						if (NULL == session->head.virus_detection_file)
						{
							return http_onsockerr(hdr, FLTEV_ONSOCKERROR, obj->buffdata.data, obj->buffdata.len);
						}
					}

					fwrite(obj->buffdata.data, obj->buffdata.len, 1, session->head.virus_detection_file);

					if (session->head.remain_bytes_cnt == session->head.content_len)
					{
						session->last_file_data = SCMalloc(obj->buffdata.len);
						memset(session->last_file_data, 0, obj->buffdata.len);
						memcpy(session->last_file_data, obj->buffdata.data, obj->buffdata.len);
						session->last_file_len = obj->buffdata.len;
						fflush(session->head.virus_detection_file);
						fclose(session->head.virus_detection_file);
						pthread_create(&pthread, NULL, thread_virus_detection, hdr);
						pthread_detach(pthread);
						return FLTRET_OK;
					}
				}
			}
		}

		if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
		{
			return http_onsockerr(hdr, FLTEV_ONSOCKERROR, obj->buffdata.data, obj->buffdata.len);
		}
	}
	return FLTRET_OK;
}

static enum FLT_RET http_onsockerr(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	struct http_session *session = hdr->user;
	SCLogInfo("http: on socket close, ssid: %d\n", hdr->sessionid);
	if (NULL != session->head.virus_detection_file)
	{
		return FLTRET_OK;
	}
	http_session_free(session);
	hdr->user = NULL;
	return FLTRET_CLOSE;
}

enum FLT_RET http_oninit()
{
	cfg = htp_config_create();

	/* register http request callback function */
	htp_config_register_request_line(cfg, callback_request_line);
	htp_config_register_request_headers(cfg, callback_request_headers);
	htp_config_register_request_body_data(cfg, callback_request_body_data);
	htp_config_register_request_trailer(cfg, callback_request_trailer);

	/* register http response callback function */
	htp_config_register_response_line(cfg, callback_response_line);
	htp_config_register_response_headers(cfg, callback_response_headers);
	htp_config_register_response_body_data(cfg, callback_response_body_data);
	htp_config_register_response_trailer(cfg, callback_response_trailer);

	/* init function point array */
	g_http_ondata_cb[FLTEV_ONCLIIN] = http_oncliin;
	g_http_ondata_cb[FLTEV_ONSVROK] = http_svrok;
	g_http_ondata_cb[FLTEV_ONSOCKDATA] = http_onsockdata;
	g_http_ondata_cb[FLTEV_ONFWDDATA] = http_onfwddata;
	g_http_ondata_cb[FLTEV_ONSOCKERROR] = http_onsockerr;

	return FLTRET_OK;
}

enum FLT_RET http_onpkt(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	return g_http_ondata_cb[ev](hdr, ev, buff, len);
}

enum FLT_RET http_onfree()
{
	return FLTRET_OK;
}

enum SVR_ID http_check_data(const void *buff, size_t len)
{
	if (len > strlen(HTTP_GET) && memcmp(buff, HTTP_GET, strlen(HTTP_GET)) == 0)
		return SVR_ID_HTTP;
	if (len > strlen(HTTP_POST) && memcmp(buff, HTTP_POST, strlen(HTTP_POST)) == 0)
		return SVR_ID_HTTP;
	if (len > strlen(HTTP_HEAD) && memcmp(buff, HTTP_HEAD, strlen(HTTP_HEAD)) == 0)
		return SVR_ID_HTTP;
	if (len > strlen(HTTP_TRACE) && memcmp(buff, HTTP_TRACE, strlen(HTTP_TRACE)) == 0)
		return SVR_ID_HTTP;
	if (len > strlen(HTTP_OPTIONS) && memcmp(buff, HTTP_OPTIONS, strlen(HTTP_OPTIONS)) == 0)
		return SVR_ID_HTTP;
	if (len > strlen(HTTP_DELETE) && memcmp(buff, HTTP_DELETE, strlen(HTTP_DELETE)) == 0)
		return SVR_ID_HTTP;
	if (len > strlen(HTTP_CONNECT) && memcmp(buff, HTTP_CONNECT, strlen(HTTP_CONNECT)) == 0)
		return SVR_ID_HTTP;

	return _SVR_ID_NONE;
}

static struct packet_filter g_filter_http = { SVR_ID_HTTP, "http parser", http_oninit, http_onpkt, http_onfree, http_check_data };

PROTOCOL_FILTER_OP(http)

