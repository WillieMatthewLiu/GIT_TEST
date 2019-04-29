#include "app_common.h"
#include "command.h"
#include "parser_ftp.h"
#include "parser_tcp.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "nlkernel.h"
#include "db_agent.h"

#include "main_inouter.h"
#include "gap_cmd.h"
#include "gap_cmd_group.h"
#include "gap_cmd_ftp.h"
#include "gap_stgy.h"
#include "parser_common.h"
#include "db_mysql.h"

#define TRUE 1
#define FALSE 0

#define FTP_RETURN_OK               0
#define FTP_RETURN_ERROR            (-1)

struct ftp_session
{
	struct server *data_svr;
	int flag_security;

	int banner_modified;
	struct ftp_rule_group *rule;
	char *ftp_user_name;
	int virus_detection; // 0: no detetion, 1: up file detection, 2: down file detection
	char *virus_detection_file_path;
	FILE *virus_detection_file;
	uint64_t max_down_filelen;
	uint64_t max_up_filelen;
	uint64_t up_bytes_cnt;
	uint64_t down_bytes_cnt;
	union {
		struct filter_header * cmd_svr_hdr;
		struct filter_header * data_svr_hdr;
	}u;
};

char tmp_buff[1460];

enum FLT_RET ftp_outer_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);
struct ftp_session* ftp_session_new()
{
	struct ftp_session *session = SCMalloc(sizeof(struct ftp_session));
	memset(session, 0, sizeof(*session));
	return session;
}

void ftp_session_free(struct ftp_session *session)
{
	//struct filter_header *related_hdr = NULL;

	if (!session)
		return;

	if (session->data_svr)
	{
		server_free(session->data_svr);
	}
	//if (session->groupname)
	//	SCFree(session->groupname);
	if (session->ftp_user_name)
		SCFree(session->ftp_user_name);

	SCFree(session);
}

struct server **port_to_server = NULL;


int set_port(struct server *svr)
{
	static int n = 0;
	int ret = -1;
	int cnt = g_gapcfg->port_ftp_end - g_gapcfg->port_ftp_begin;

	for (int i = 0; i < cnt; i++)
	{
		n = n % cnt;
		if (port_to_server[n] == 0)
		{
			port_to_server[n] = svr;
			ret = n++;
			break;
		}
		else
			n++;
	}
	if (ret == -1)
		return -1;
	return ret + g_gapcfg->port_ftp_begin;
}

int find_port(struct server *svr)
{
	int i;
	int cnt = g_gapcfg->port_ftp_end - g_gapcfg->port_ftp_begin;
	for (i = 0; i < cnt; i++)
	{
		if (port_to_server[i] == svr)
		{
			return 0;
		}
	}
	return -1;
}

void delete_port(struct server *svr)
{
	int i;
	int cnt = g_gapcfg->port_ftp_end - g_gapcfg->port_ftp_begin;
	for (i = 0; i < cnt; i++)
	{
		if (port_to_server[i] == svr)
		{
			port_to_server[i] = NULL;
		}
	}
}

int strarr(char *str, char *dst, char **arr, int cnt)
{
	int ret = 0;
	char *ctx = NULL;

	for (char *p = strtok_r(str, dst, &ctx); p != NULL; p = strtok_r(NULL, dst, &ctx))
	{
		if (ret >= cnt)
			break;
		arr[ret++] = p;
	}
	return ret;
}

void pasv_get_port(char *str, uint8_t *p1, uint8_t *p2, char *ip)
{
	char *arr[10];
	int ret = strarr(str, ",", arr, 10);
	assert(ret == 6);
	*p1 = (uint8_t)atoi(arr[4]);
	*p2 = (uint8_t)atoi(arr[5]);

	if (ip != NULL)
	{
		arr[0] = strchr(arr[0], ' ');
		sprintf(ip, "%d.%d.%d.%d", atoi(arr[0]), atoi(arr[1]), atoi(arr[2]), atoi(arr[3]));
	}
}

int get_ftp_port(const char *cmd, char *addr)
{
	uint8_t p1 = 0, p2 = 0;
	char dst_ip[20] = { 0 };
	pasv_get_port((char*)cmd, &p1, &p2, dst_ip);
	uint16_t server_port = p1 * 256 + p2;
	sprintf(addr, "%s:%d", dst_ip, server_port);
	return 0;
}

int security_check_ftp(struct filter_header *hdr, char *buff)
{
	struct ftp_session *session = hdr->user;
	if (strcasecmp(buff, "user") != 0 &&
		strcasecmp(buff, "opts") != 0)
	{
		return -1;
	}
	else
		session->flag_security = 1;
	return 0;
}

int get_ftp_cmd(const void *buff, size_t len, char *cmd, size_t sz)
{
	size_t n = len;
	char *p = strchr((char*)buff, ' ');
	char *end = strstr((char*)buff, "\r\n");
	if (p != NULL)
		n = (size_t)(p - (char*)buff);
	else
		n = (size_t)(end - (char*)buff);
	if (n > sz)
		n = sz - 1;
	memcpy(cmd, buff, n);
	cmd[n] = '\0';

	return 0;
}

void str_replace(char *str, char ch1, char ch2)
{
	while (*str)
	{
		if (*str == ch1)
			*str = ch2;
		str++;
	}
}

int create_datasvr_port(struct filter_header *hdr, uint16_t server_port, char *dst_ip, char *local_ip)
{
	int ret = 0;
	struct ftp_session *session = hdr->user;
	struct server *svr = server_new(SVR_ID_FTPDATA, "ftp data server", local_ip, 0, dst_ip, server_port);
	if (svr == NULL)
		return -1;

	if ((ret = set_port(svr)) == -1)
	{
		return -1;
	}
	else
	{
		svr->localport = ret;
	}

	hdr->svr_add_cb(hdr, svr);

	if (session->data_svr != NULL)
	{
		hdr->svr_remove_cb(hdr, session->data_svr);
		delete_port(session->data_svr);
		server_free(session->data_svr);
	}
	session->data_svr = svr;
	return 0;
}

int create_datasvr_pasv(struct filter_header *hdr, uint16_t server_port)
{
	int ret = 0;
	struct ftp_session *session = hdr->user;
	struct server *svr = server_new(SVR_ID_FTPDATA, "ftp data server", hdr->svr->localip, 0, hdr->svr->dstip, server_port);
	if (svr == NULL)
		return -1;

	if ((ret = set_port(svr)) == -1)
	{
		return -1;
	}
	else
	{
		svr->localport = ret;
	}

	hdr->svr_add_cb(hdr, svr);

	if (session->data_svr != NULL)
	{
		hdr->svr_remove_cb(hdr, session->data_svr);
		delete_port(session->data_svr);
		server_free(session->data_svr);
	}
	session->data_svr = svr;
	return 0;
}

void del_prev_svr(struct filter_header *hdr)
{
	struct ftp_session *session = hdr->user;
	hdr->svr_remove_cb(hdr, session->data_svr);
	delete_port(session->data_svr);
	SCFree(session->data_svr->name);
	SCFree(session->data_svr->dstip);
	SCFree(session->data_svr->localip);
	SCFree(session->data_svr);
	session->data_svr = NULL;
}

int get_inner_ip(struct filter_header *hdr, char *ip)
{
#if 0
	strcpy(hdr->dstif, "eth0");
	struct eth_item *ecfg = gapconfig_getethbyname(hdr->dstif);
	ecfg->vip = inet_addr("192.168.40.11");
#else
	struct interface *ifp = gapconfig_get_if_by_name(hdr->dstif);
#endif
	if (ifp == NULL)
		return -1;
	addr2str(if_get_vip(ifp), ip);

	return 0;
}

/* Strat:   Problem NO.(MAG-170), liuzongquan(000932), 2016.12.27 */
static int get_port_element(char *data, int len, uint8_t *p1, uint8_t *p2, char *ip)
{
	char *crlf = NULL;
	char *analyBuff = NULL;

	analyBuff = (char *)SCMalloc(len);
	if (NULL == analyBuff)
	{
		SCLogError("FTP[ERROR]: SCMalloc memory failed, size(%d)", len);
		return FTP_RETURN_ERROR;
	}
	memcpy(analyBuff, data, len);

	crlf = strstr(analyBuff, "\r\n");
	if (NULL != crlf)
	{
		*crlf = 0;
	}

	pasv_get_port(analyBuff, p1, p2, ip);
	SCFree(analyBuff);
	analyBuff = NULL;

	return FTP_RETURN_OK;
}
/* End:     Problem NO.(MAG-170), liuzongquan(000932), 2016.12.27 */




static int get_user_name(struct ftp_session *session, const char *buff)
{
	int ret = -1;
	size_t n = 0;
	char *p = strchr((char*)buff, ' ');
	char *end = strstr(buff, "\r\n");
	if (p != NULL && end != NULL)
	{
		p++;
		n = (size_t)(end - p);

		session->ftp_user_name = SCMalloc(n + 1);
		if (!session->ftp_user_name)
			return -1;
		memcpy(session->ftp_user_name, p, n);
		session->ftp_user_name[n] = '\0';
		ret = 0;
	}

	return ret;
}

static int get_file_name(char *filename, size_t len, const char *buff, size_t size)
{
	int ret;
	size_t n = 0;
	char *p = strchr((char*)buff, ' ');
	char *end = strstr(buff, "\r\n");

	if (p != NULL && end != NULL)
	{
		p++;
		n = (size_t)(end - p);

		if (n > len)
			n = len - 1;
		memcpy(filename, p, n);
		filename[n] = '\0';
		ret = 0;
	}
	return ret;
}

static void ftp_write_secauditlog(struct filter_header *hdr, int level, char *rule, char *content)
{
	char sip[20];
	char dip[20];
	char *user = NULL;
	uint32_t *autoId = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	user = hdr->username ? hdr->username : "none";
	GET_AUTO_ID_BY_HDR(hdr, &autoId);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, hdr->tcp->source, hdr->tcp->dest, "FTP",
		user, "none", level, rule, "权限被拒绝", strlen(content), content);
}

static int reponse_err(struct filter_header *hdr, const char *buff, int len)
{
	int ret;
	ret = buffer_sendtoreq(hdr, "500 permission denied\r\n", 23);
	if (ret)
		return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
	return FLTRET_OK;
}

enum FLT_RET ftp_outer_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	/* FLTEV_ONCLIIN client in */
	if (ev == FLTEV_ONCLIIN)
	{
		struct ftp_session *session = ftp_session_new();
		hdr->user = session;

		SCLogInfo("FTPCMD: on client in, dstport: %d, ssid: %d", ntohs(hdr->tcp->dest), hdr->sessionid);
		return FLTRET_OK;
	}

	/* FLTEV_ONSVROK server connect success/failure */
	if (ev == FLTEV_ONSVROK)
	{
		struct ftp_session *session = hdr->user;
		struct acl_data *ad = hdr->private;
		//struct tlvhdr *hdrgname = NULL;

		int isok = *((int*)buff); assert(len == sizeof(isok));
		SCLogInfo("FTPCMD: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

		if (isok == 0)
			return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);

		/* get ftp_rule_group from groupname */
		if (ad && ad->group)
		{
			SCLogInfo("FTPCMD: gname: %s\n", ad->groupname);
			session->rule = ad->group->acl[SVR_ID_FTP].protocol_rule;
		}

		return FLTRET_OK;
	}

	/* FLTEV_ONFWDDATA receive data from fwd */
	if (ev == FLTEV_ONFWDDATA)
	{
		struct ftp_session *session = hdr->user;
		struct tlvhdr *hdr_virus_detection = NULL;
		struct tlvhdr *hdr_max_filelen = NULL;
		char tmp[1024] = { 0 };
		ForwardObject *obj = (ForwardObject*)buff; assert(len == sizeof(obj));

		if (obj->cmd == FWDCMD_FORWARDDATA)
		{
			//SCLogInfo("FTPCMD: on fwd data:%s,len:%d,sessionid=%d", obj->buffdata.data, obj->buffdata.len, hdr->sessionid);

			assert(obj->has_buffdata);
			/* run on router of cmd channel，receive pasv-module port info from fwd of the server，build data_server on the router of cmd channel */
			if (hdr->svr != NULL)
			{
				/* replace banner info */
				if (!session->banner_modified && session->rule && !strncmp((char*)obj->buffdata.data, "220", 3))
				{
					session->banner_modified = 1;
					memcpy(tmp, "220 ", 4);
					if (ftp_get_banner_info(session->rule, tmp + 4, sizeof(tmp) - 4))
					{
						obj->buffdata.data = (uint8_t*)tmp;
						obj->buffdata.len = strlen(tmp);
					}
				}

				if (strncmp((char*)obj->buffdata.data, "227 Entering Passive", 20) == 0)
				{
					uint8_t p1 = 0, p2 = 0;

					if (FTP_RETURN_OK != get_port_element((char*)obj->buffdata.data, (int)obj->buffdata.len, &p1, &p2, NULL))
					{
						return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
					}

					uint16_t server_port = p1 * 256 + p2;

					/* create the data server and delete the previous server */
					if (create_datasvr_pasv(hdr, server_port) != 0)
					{
						return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
						
					int n = sprintf(tmp, "227 Entering Passive Mode (%s,%d,%d)\r\n", hdr->svr->localip, (session->data_svr->localport) / 256, (session->data_svr->localport) % 256);
					str_replace(tmp, '.', ',');
					obj->buffdata.data = (uint8_t*)tmp;
					obj->buffdata.len = n;
					
					SCLogInfo("FTPCMD: local_ip=%s, local_port=%d, dest_ip=%s, dest_port=%d, sessionid=%d",session->data_svr->localip, session->data_svr->localport, session->data_svr->dstip, session->data_svr->dstport, hdr->sessionid);
					SCLogInfo("FTPCMD: tmp=%s, sessionid=%d", tmp,hdr->sessionid);
				}
			}
			/* run on non-router of cmd channel，receive port-module port info from server，build data_server on the non-router of cmd channel */
			else if (hdr->svr == NULL)
			{
				if (strncasecmp((char*)obj->buffdata.data, "PORT ", 5) == 0)
				{
					uint8_t p1 = 0, p2 = 0;
					char dst_ip[20] = { 0 };
					char loc_ip[20] = { 0 };

					/* Strat:   Problem NO.(MAG-170), liuzongquan(000932), 2016.12.27 */
					if (FTP_RETURN_OK != get_port_element((char*)obj->buffdata.data, (int)obj->buffdata.len, &p1, &p2, dst_ip))
					{
						return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
					}
					/* End:     Problem NO.(MAG-170), liuzongquan(000932), 2016.12.27 */

					uint16_t server_port = p1 * 256 + p2;

					inet_ntop(AF_INET, &hdr->localip, loc_ip, 20);

					/* get the non-router local ip */
					/*if (get_inner_ip(hdr, loc_ip) != 0)
					{
						return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
					}*/
						
					if (create_datasvr_port(hdr, server_port, dst_ip, loc_ip) != 0)
						return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);

					int n = sprintf(tmp, "PORT %s,%d,%d\r\n", session->data_svr->localip, (session->data_svr->localport) / 256, (session->data_svr->localport) % 256);
					str_replace(tmp, '.', ',');
					obj->buffdata.data = (uint8_t*)tmp;
					obj->buffdata.len = n;
					
					SCLogInfo("FTPCMD: local_ip=%s, local_port=%d, dest_ip=%s, dest_port=%d, sessionid=%d",session->data_svr->localip, session->data_svr->localport, session->data_svr->dstip, session->data_svr->dstport, hdr->sessionid);
					SCLogInfo("FTPCMD: tmp=%s, sessionid=%d", tmp,hdr->sessionid);
				}

				hdr_virus_detection = tlvbox_find(hdr->tlv_in, TLV_FTP_VIRUS_DETECTION);
				hdr_max_filelen = tlvbox_find(hdr->tlv_in, TLV_FTP_UP_FILELEN);
				if (hdr_virus_detection)
				{
					session->virus_detection = tlv_get_uint32(hdr_virus_detection);
					SCLogInfo("FTPCMD: virus_detection: %d\n", session->virus_detection);
				}
				if (hdr_max_filelen)
				{
					session->max_up_filelen = tlv_get_uint64(hdr_max_filelen);
					SCLogInfo("FTPCMD: max_up_filelen: %ld\n", session->max_up_filelen);
				}

			}

			int ret = buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len);
			if (ret != 0)
				return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		return FLTRET_OK;
	}

	/* FLTEV_ONSOCKDATA receive data from client or server */
	if (ev == FLTEV_ONSOCKDATA)
	{
		struct ftp_session *session = hdr->user;
		char cmd[1024] = { 0 };
		char filename[1024] = { 0 };
		char *filetype = NULL;
		char ip_src[20] = { 0 };
		char ip_dst[20] = { 0 };
		addr2str(hdr->ip->daddr, ip_dst);
		addr2str(hdr->ip->saddr, ip_src);
		char *proto = (char*)server_strfromid(SVR_ID_FTP);
		int ret;

		/* run on router of cmd channel */
		if ((buff != NULL) && (hdr->svr != NULL))
		{
			/* get ftp cmd */
			if (get_ftp_cmd(buff, len, cmd, sizeof(cmd)) != 0)
				return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			/* ftp security check */
			if ((session->flag_security == 0) && (security_check_ftp(hdr, cmd) != 0))
			{
				char *err = "Format check failed";
				write_secevent_log(ip_src, ip_dst, hdr->username, proto, SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, "", PRI_HIGH, 0);
				return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}

			if (session->rule && session->rule->rule_work)
			{
				/* get ftp user, and check user's privilege */
				if (!session->ftp_user_name && (strcmp(cmd, "USER") == 0) && !get_user_name(session, buff))
				{
					SCLogInfo("FTPCMD: USER: %s\n", session->ftp_user_name);
					if (ftp_check_user_privilege(session->rule, session->ftp_user_name))
					{
						ftp_write_secauditlog(hdr, l_critical, "account", session->ftp_user_name);
						return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, NULL, 0);
					}
				}

				/* check cmd's privilege */
				if (ftp_check_cmd_privilege(session->rule, cmd))
				{
					ftp_write_secauditlog(hdr, l_warn, "command", cmd);
					ret = reponse_err(hdr, buff, len);
					return ret;
				}

				/* check up file */
				if (!strcmp(cmd, "STOR"))
				{
					/* check up file type */
					if (!get_file_name(filename, sizeof(filename), buff, len))
					{
						filetype = strchr(filename, '.');
						if (filetype)
							ret = ftp_check_upfile_type_privilege(session->rule, filetype);
						else
							ret = ftp_check_upfile_type_privilege(session->rule, ".");
						if (ret)
						{
							ftp_write_secauditlog(hdr, l_warn, "up file type", filename);
							ret = reponse_err(hdr, buff, len);
							return ret;
						}
					}

					/* get max upfile length */
					session->max_up_filelen = ftp_get_max_upfile_length(session->rule);
					tlvbox_put_uint64(hdr->tlv_out, TLV_FTP_UP_FILELEN, session->max_up_filelen);

					/* check if need up file virus detection */
					if (ftp_check_upfile_virus_detection(session->rule))
						session->virus_detection = 1;
					else
						session->virus_detection = 0;
					tlvbox_put_uint32(hdr->tlv_out, TLV_FTP_VIRUS_DETECTION, session->virus_detection);

					SCLogInfo("FTPCMD: up virus_detection: %d\n", session->virus_detection);

				}

				/* check down file */
				if (!strcmp(cmd, "RETR") && !get_file_name(filename, sizeof(filename), buff, len))
				{
					filetype = strchr(filename, '.');
					if (filetype)
						ret = ftp_check_downfile_type_privilege(session->rule, filetype);
					else
						ret = ftp_check_downfile_type_privilege(session->rule, ".");
					if (ret)
					{
						ftp_write_secauditlog(hdr, l_warn, "down file type", filename);
						ret = reponse_err(hdr, buff, len);
						return ret;
					}

					/* told another side the max downfile length */
					session->max_down_filelen = ftp_get_max_downfile_length(session->rule);

					/* check if need down file virus detection, and told another side */
					if (ftp_check_downfile_virus_detection(session->rule))
						session->virus_detection = 2;
					else
						session->virus_detection = 0;

					SCLogInfo("FTPCMD: down virus_detection: %d\n", session->virus_detection);
					SCLogInfo("FTPCMD: max_down_filelen: %ld\n", session->max_down_filelen);
				}
			}

		}

		if (buffer_sendtofwd(hdr, buff, len) != 0)
			return ftp_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);

		return FLTRET_OK;
	}

	/* FLTEV_ONSOCKERROR connection close */
	if (ev == FLTEV_ONSOCKERROR)
	{
		struct ftp_session *session = hdr->user;
		SCLogInfo("FTPCMD: on socket close, ssid: %d", hdr->sessionid);
		if (session == NULL)
			return FLTRET_CLOSE;
		/* no free session，no return FLTRET_CLOSE, no notice client close */
		if (session->data_svr != NULL)
		{
			hdr->svr_remove_cb(hdr, session->data_svr);
			delete_port(session->data_svr);
		}

		ftp_session_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}
	return FLTRET_OK;
}

int ftp_outer_oninit()
{
	return 0;
}

int ftp_outer_onfree()
{
	return 0;
}



int ftp_isdataport(uint16_t port)
{
	return (port >= g_gapcfg->port_ftp_begin) && (port <= g_gapcfg->port_ftp_end);
}

void *thread_send_file_toreq(void *args)
{
	int fd, length;
	struct filter_header *hdr = (struct filter_header *)args;
	struct ftp_session *session = hdr->user;

	/* virus detection */
	if (!ftp_file_virus_detection(session->virus_detection_file_path))
	{
		fd = get_sockfd_byhdr(hdr);
		while ((length = fread(tmp_buff, 1, sizeof(tmp_buff), session->virus_detection_file)) > 0)
		{
			socket_syncsend(fd, tmp_buff, length);
			//SCLogInfo("FTPDATA: sendtofwd: %d", length);
		}
	}
	else
		ftp_write_secauditlog(hdr, l_critical, "virus detection", session->virus_detection_file_path);

	fflush(session->virus_detection_file);
	fclose(session->virus_detection_file);
	SCLogInfo("rm temp file %s\n", session->virus_detection_file_path);
	cmd_system_novty_arg("rm -rf %s", session->virus_detection_file_path);
	SCFree(session->virus_detection_file_path);
	session->virus_detection_file = NULL;
	session->up_bytes_cnt = 0;
	session->down_bytes_cnt = 0;
	sessionmap_postclose_byhdr(hdr);
	return NULL;
}

enum FLT_RET ftpdata_outer_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	/* FLTEV_ONCLIIN client in */
	if (ev == FLTEV_ONCLIIN)
	{
		struct ftp_session *session = ftp_session_new();
		struct ftp_session *cmd_session = NULL;
		struct filter_header *cmd_hdr = NULL;
		struct tlvhdr *hdr_parent_sessionid = NULL;
		uint32_t parent_sessionid = 0;

		hdr->user = session;

		SCLogInfo("FTPDATA: on client in, dstport: %d, ssid: %d", ntohs(hdr->tcp->dest), hdr->sessionid);

		if (hdr->svr)
		{
			cmd_hdr = sessionmap_gethdr_fromid(hdr->svr->parent_sesssionid);
			SCLogInfo("FTPDATA: cmd_hdr: %p, parent_sesssionid: %d\n", cmd_hdr, hdr->svr->parent_sesssionid);
			if (cmd_hdr)
			{
				cmd_session = cmd_hdr->user;
				cmd_session->u.data_svr_hdr = hdr;
				session->u.cmd_svr_hdr = cmd_hdr;
				tlvbox_put_uint32(hdr->tlv_out, TLV_FTP_PARENT_SESSIONID, hdr->svr->parent_sesssionid);
			}
			SCLogInfo("FTPDATA: 1.parent_sesssionid: %d, cmd_session: %p\n", hdr->svr->parent_sesssionid, cmd_session);
		}
		else
		{
			hdr_parent_sessionid = tlvbox_find(hdr->tlv_in, TLV_FTP_PARENT_SESSIONID);
			if (hdr_parent_sessionid)
			{
				parent_sessionid = tlv_get_uint32(hdr_parent_sessionid);
				cmd_hdr = sessionmap_gethdr_fromid(parent_sessionid);
				if (cmd_hdr)
				{
					cmd_session = cmd_hdr->user;
					cmd_session->u.data_svr_hdr = hdr;
					session->u.cmd_svr_hdr = cmd_hdr;
				}
			}
			SCLogInfo("FTPDATA: 2.parent_sesssionid: %d\n", parent_sessionid);
		}

		return FLTRET_OK;
	}

	/* FLTEV_ONSVROK server connect success/failure */
	if (ev == FLTEV_ONSVROK)
	{
		int isok = *((int*)buff); 
		
		assert(len == sizeof(isok));
		SCLogInfo("FTPDATA: connect server ret: %d, ssid: %d", isok, hdr->sessionid);

		if (isok == 0)
		{
			return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
			
		struct ftp_session *session = hdr->user;
		struct acl_data *ad = hdr->private;
		
		/* get ftp_rule_group from groupname */
		if (ad && ad->group)
		{
			SCLogInfo("FTPCMD: gname: %s\n", ad->groupname);
			session->rule = ad->group->acl[SVR_ID_FTP].protocol_rule;
		}		

		return FLTRET_OK;
	}

	/* FLTEV_ONFWDDATA receive data from fwd */
	if (ev == FLTEV_ONFWDDATA)
	{
		// 收到内端机的数据，buff指向对应的FowardObject对象，len一定为sizeof(void*)
		
		ForwardObject *obj = (ForwardObject*)buff; assert(len == sizeof(obj));
		//SCLogInfo("FTPDATA: on fwd data:%s,len:%d,sessionid=%d", obj->buffdata.data, obj->buffdata.len, hdr->sessionid);
		struct ftp_session *session = hdr->user;
		struct ftp_session *cmd_session = NULL;
		struct filter_header *cmd_hdr = session->u.cmd_svr_hdr;
		char filename[1024] = { 0 };

		if (cmd_hdr && (cmd_session = cmd_hdr->user) && cmd_session->rule && cmd_session->rule->rule_work)
		{
			if (!cmd_hdr->svr)
			{
				/* check up file length privilege */
				session->up_bytes_cnt += obj->buffdata.len;
				if (cmd_session->max_up_filelen && (session->up_bytes_cnt > cmd_session->max_up_filelen))
				{
					ftp_write_secauditlog(hdr, l_critical, "up file length", filename);
					if (session->virus_detection_file)
					{
						fclose(session->virus_detection_file);
						session->virus_detection_file = NULL;
						cmd_system_novty_arg("rm -rf %s", session->virus_detection_file_path);
					}
					return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, obj->buffdata.data, obj->buffdata.len);
				}

				/* cache vitus detection file */
				if (cmd_session->virus_detection == 1)
				{
					if (!session->virus_detection_file)
					{
						snprintf(filename, sizeof(filename), "%s%d", FTP_VIRUS_DETECTION_FILE_PRE, hdr->sessionid);
						session->virus_detection_file_path = SCStrdup(filename);
						if (!session->virus_detection_file_path)
						{
							return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, NULL, 0);
						}							

						session->virus_detection_file = fopen(session->virus_detection_file_path, "w+");
						if (!session->virus_detection_file)
						{
							return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, NULL, 0);
						}							
					}

					fwrite(obj->buffdata.data, obj->buffdata.len, 1, session->virus_detection_file);
					return FLTRET_OK;
				}
			}
			else
			{
				/* check down file length privilege */
				session->down_bytes_cnt += obj->buffdata.len;
				if (cmd_session->max_down_filelen && (session->down_bytes_cnt > cmd_session->max_down_filelen))
				{
					ftp_write_secauditlog(hdr, l_critical, "down file length", filename);
					if (session->virus_detection_file)
					{
						fclose(session->virus_detection_file);
						session->virus_detection_file = NULL;
						cmd_system_novty_arg("rm -rf %s", session->virus_detection_file_path);
					}
					return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, obj->buffdata.data, obj->buffdata.len);
				}

				/* cache vitus detection file */
				if (cmd_session->virus_detection == 2)
				{
					if (!session->virus_detection_file)
					{
						snprintf(filename, sizeof(filename), "%s%d", FTP_VIRUS_DETECTION_FILE_PRE, hdr->sessionid);
						session->virus_detection_file_path = SCStrdup(filename);
						if (!session->virus_detection_file_path)
						{
							return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, NULL, 0);
						}
							
						session->virus_detection_file = fopen(session->virus_detection_file_path, "w+");
						if (!session->virus_detection_file)
						{
							return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, NULL, 0);
						}							
					}

					fwrite(obj->buffdata.data, obj->buffdata.len, 1, session->virus_detection_file);
					return FLTRET_OK;
				}
			}
		}

		if (obj->cmd == FWDCMD_FORWARDDATA)
		{
			//转发数据，ForwardObject::buffdata有效, ForwardObject::strdata有效，为具体待判断的行为信息			
			assert(obj->has_buffdata);
			
			if (session->rule == NULL)
			{
				struct acl_data *ad = hdr->private;
		
				/* get ftp_rule_group from groupname */
				if (ad && ad->group)
				{
					//SCLogInfo("FTPCMD: gname:%d %s %s\n", __LINE__, __FUNCTION__, ad->groupname);
					SCLogInfo("FTPCMD: gname: %s %d %s %s\n", __FILE__, __LINE__, __FUNCTION__, ad->groupname);
					session->rule = ad->group->acl[SVR_ID_FTP].protocol_rule;
				}		
			}
			
			if (session->rule != NULL)
			{
				int nReturn = ftp_check_keyword(session->rule, obj->buffdata.data, obj->buffdata.len);
				if (nReturn > 0)
				{
					//找到关键字
					nReturn--;
					char chBuffer[128] = { 0 };
					snprintf(chBuffer, 128, "传输内容包含过滤关键字:%s", &session->rule->chKeyWord[nReturn * 40]);

					INSERT_SYS_LOG("FTP代理", l_warn, chBuffer);

					return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, obj->buffdata.data, obj->buffdata.len);
				}
			}
			
			int ret = buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len);
			if (ret != 0)
			{
				return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}				
		}

		return FLTRET_OK;
	}

	/* FLTEV_ONSOCKDATA receive data from client or server */
	if (ev == FLTEV_ONSOCKDATA)
	{		
		// 收到SOCKET的数据，buff指向数据内容，len为数据长度
		struct ftp_session* pSession = hdr->user;
		
		if (pSession->rule == NULL)
		{
			struct acl_data* ad = hdr->private;
		
			/* get ftp_rule_group from groupname */
			if (ad && ad->group)
			{
				//SCLogInfo("FTPCMD: gname:%d %s %s\n", __LINE__, __FUNCTION__, ad->groupname);
				SCLogInfo("FTPCMD: gname: %s %d %s %s\n", __FILE__, __LINE__, __FUNCTION__, ad->groupname);
				pSession->rule = ad->group->acl[SVR_ID_FTP].protocol_rule;
			}		
		}

		if (pSession->rule != NULL)
		{
			int nReturn = ftp_check_keyword(pSession->rule, buff, len);
			if (nReturn > 0)
			{
				//找到关键字
				nReturn--;
				char chBuffer[128] = { 0 };
				snprintf(chBuffer, 128, "传输内容包含过滤关键字:%s", &pSession->rule->chKeyWord[nReturn * 40]);

				INSERT_SYS_LOG("FTP代理", l_warn, chBuffer);

				return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
			}
		}
			
		if (buffer_sendtofwd(hdr, buff, len) != 0)
		{
			return ftpdata_outer_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
			
		return FLTRET_OK;
	}

	/* FLTEV_ONSOCKERROR connection close */
	if (ev == FLTEV_ONSOCKERROR)
	{
		//int length;
		pthread_t pthread;
		struct ftp_session *session = hdr->user;
		SCLogInfo("FTPDATA: on socket close, ssid: %d", hdr->sessionid);
		SCLogInfo("FTPDATA: up_bytes_cnt: %ld", session->up_bytes_cnt);
		SCLogInfo("FTPDATA: down_bytes_cnt: %ld", session->down_bytes_cnt);

		if (session->virus_detection_file)
		{
			SCLogInfo("FTPDATA: found virus_detection_file\n");
			fflush(session->virus_detection_file);
			fseek(session->virus_detection_file, 0, SEEK_SET);

			pthread_create(&pthread, NULL, thread_send_file_toreq, hdr);
			return FLTRET_OK;
		}

		ftp_session_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}
	return FLTRET_OK;
}

int ftpdata_outer_oninit()
{
	int cnt = g_gapcfg->port_ftp_end - g_gapcfg->port_ftp_begin;
	port_to_server = SCMalloc(sizeof(struct server*) * cnt);
	memset(port_to_server, 0, sizeof(struct server*) * cnt);

	return 0;
}

int ftpdata_outer_onfree()
{
	SCFree(port_to_server);
	return 0;
}

enum SVR_ID ftp_check_data(const void *buff, size_t len)
{
	if (len >= 4)
	{
		char code[5] = { 0 }; memcpy(code, buff, 4);
		if (atoi(code) == 220)
			return SVR_ID_FTP;
	}
	return _SVR_ID_NONE;
}

static struct packet_filter g_filter_ftp = { SVR_ID_FTP, "ftp outer parser", ftp_outer_oninit, ftp_outer_ondata, ftp_outer_onfree, ftp_check_data };
static struct packet_filter g_filter_ftpdata = { SVR_ID_FTPDATA, "ftpdata outer parser", ftpdata_outer_oninit, ftpdata_outer_ondata, ftpdata_outer_onfree };

void parser_ftp_pktfilter_reg()
{
	pktfilter_reg(&g_filter_ftp);
	pktfilter_reg(&g_filter_ftp);
}

void parser_ftp_pktfilter_unreg()
{
	pktfilter_unreg(&g_filter_ftp);
	pktfilter_unreg(&g_filter_ftp);
}

void parser_ftpdata_pktfilter_reg()
{
	pktfilter_reg(&g_filter_ftpdata);
	pktfilter_reg(&g_filter_ftpdata);
}

void parser_ftpdata_pktfilter_unreg()
{
	pktfilter_unreg(&g_filter_ftpdata);
	pktfilter_unreg(&g_filter_ftpdata);
}

