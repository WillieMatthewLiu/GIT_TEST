#ifndef _PARSER_HTTP_H
#define _PARSER_HTTP_H
#include <htp/htp.h>
#include "pktfilter.h"
#pragma once

#define HEAD_LEN 2048
#define METHOD_LEN 64
#define URL_LEN 512
#define MIME_LEN 64
#define OUT_IPPORT_LEN 64
#define FILE_NAME_LEN 1024

typedef enum FLT_RET(*HTTP_SOCK_FUNC)(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len);

struct http_filter
{
	/* head info */
	char *method;
	char *mime;
	char *url;
	uint32_t head_len;
	uint64_t content_len;
	char *charset;
	/* file info */
	char *file_name;
	int flag_download_file;
	int flag_virus;
	int virus_detection; //0: no detection, 1: detection
	char *virus_detection_file_path;
	FILE *virus_detection_file;
	uint64_t remain_bytes_cnt;
	/* user info */
	uint64_t user_num;
};

struct http_session
{
	struct evbuffer *buf;
	struct evbuffer *buf_head;
	struct evbuffer *buf_tmp;
	htp_connp_t *conn;
	HTTP_SOCK_FUNC http_state_func;
	int http_rule_work;
	struct http_rule_group *rule;
	struct http_filter head;
	char extra[OUT_IPPORT_LEN];
	char url_file_name[FILE_NAME_LEN];
	char *url_file_type;
	char *last_file_data;
	int last_file_len;
};



#endif
