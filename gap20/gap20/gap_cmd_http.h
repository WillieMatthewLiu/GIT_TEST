#ifndef _GAP_CMD_HTTP_H
#define _GAP_CMD_HTTP_H
#include "util-list.h"
#include "gap_cmd.h"
#include "parser_http.h"
#include "gap_cmd_timemgr.h"

#define HTTP_VIRUS_DETECTION_TOOL_PATH "/home/root/ruising/"
#define HTTP_VIRUS_DETECTION_FILE_PRE "/run/http_tmp"

struct http_list_item
{
	struct list_head n_list;
	char *name;
};

struct http_rule_group
{
	char groupname[NAME_LEN + 1];
	struct gap_group_rule *group;
	int rule_work; //0: all rule don' work, 1: all rule work
	struct json_object *rule_json; //json

	/* head info */
	/* cmd */
	char *black_cmd_str;
	struct list_head cmd_table;
	/* url */
	int url_rule_mode;
	char *url_str;
	struct list_head url_table;
	/* mime */
	char *black_mime_str;
	struct list_head mime_table;
	/* length */
	int length_rule_mode;
	uint32_t max_http_head_len;

	/* content info */
	/* keyword */
	char *black_keyword_str;
	struct list_head keyword_table;
	/* script */
	int script_rule_mode;
	/* applet */
	int applet_rule_mode;
	/* activex */
	int activex_rule_mode;

	/* file info */
	int file_download_mode;
	/* length */
	int length_download_mode;
	uint64_t max_download_file_len;
	/* download file type */
	char *file_type_str;
	struct list_head file_type_table;
	int virus_detection;

	/* time control */
	char effectime[NAME_LEN + sizeof(TIME_GROUP_SUFFIX)];
	int user_num_mode;
	uint64_t max_user_access_num;
	struct time_acl tacl;
};

/* file write */
int http_config_write(struct vty *vty);
int http_check_rule_work_privilege(struct http_rule_group *group);
int http_check_effectime(struct http_rule_group *group);
int http_check_user_num(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head);
int http_check_rqst_head_privilege(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head);
int http_check_resp_head_privilege(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head);
int http_check_content_privilege(struct http_rule_group *group, const char *buf, const char *charset);
int http_check_file_privilege(struct http_rule_group *group);
int http_check_file_type_privilege(struct filter_header *hdr, struct http_rule_group *group, char *file_type);
int http_check_file_length_privilege(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head);
int http_check_file_virus_detection(struct http_rule_group *group);
int http_file_virus_detection(char *filepath);
void http_del_rule_group(void *group_rule);

void http_cmd_init(void);
void http_cmd_exit(void);

#endif 
