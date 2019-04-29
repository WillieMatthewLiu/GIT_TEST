#include "app_common.h"
#include <zebra.h>
#include <json-c/json.h>
#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/time.h>
#include <iconv.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <termios.h>
#include "command.h"
#include "lib/memory.h"
#include "buffer.h"
#include "vtysh/vtysh.h"
#include "log.h"
#include "if.h"
#include "network.h"
#include "jhash.h"
#include <pthread.h>
#include <string.h>
#include "command.h"
#include "thread.h"
#include "vty.h"
#include "swe_ver.h"
#include "ha.h"
#include "gap_ctl_ha.h"
#include "gap_ctl.h"
#include "gap_ctl_adapter.h"
#include "main_inouter.h"
#include "gap_cmd_http.h"
#include "parser_http.h"
#include "pktfilter.h"
#include "gap_cmd_group.h"
#include "json-c.h"
#include "hash.h"

#define SCRIPT "<script"
#define APPLET "<applet"
#define ACTIVEX "<object"
#define OUT_LEN 1024
#define UTF8 "utf-8"

extern struct thread_master *master;
extern int check_time_privilege(struct time_acl *tacl);
extern void timemgr_put(struct time_acl *acl);
extern void timemgr_get(struct time_acl *acl, char *name);

/*
 *	Hash table: for http lookups
 */
struct hash *http_table;
typedef unsigned(*hash_fun)(const char *name);
pthread_rwlock_t http_lock;


static unsigned int http_hashkey(struct http_rule_group *group)
{
	return jhash(group->groupname, strlen(group->groupname), 0);
}

static int http_hashcmp(const struct http_rule_group *group1, const struct http_rule_group *group2)
{
	return !strcmp(group1->groupname, group2->groupname);
}

static void http_write_pvty(struct hash_backet *bug, struct vty *vty)
{
	struct http_rule_group *group = bug->data;
	if (NULL != group)
	{
		if (NULL != group->rule_json)
		{
			vty_out(vty, "protocol-http add rule %s%s", JSON_FORMAT_STR(group->rule_json), VTY_NEWLINE);
		}
	}
}

static void http_show_pvty(struct hash_backet *bug, struct vty *vty)
{
	struct http_rule_group *group = bug->data;
	if (NULL != group)
	{
		if (NULL != group->rule_json)
		{
			vty_out(vty, "%s%s", JSON_FORMAT_STR(group->rule_json), VTY_NEWLINE);
		}
	}
}

static void http_add_rule_group(struct http_rule_group *group)
{
	hash_get(http_table, group, hash_alloc_intern);
}

void http_del_rule_group(void *group_rule)
{
	if (NULL == group_rule)
		return;

	struct http_rule_group *group = (struct http_rule_group*)group_rule;
	struct http_list_item *item = NULL;
	struct http_list_item *item_n = NULL;

	SET_PROTOCOL_RULE_NULL(group->group, SVR_ID_HTTP);
	pthread_rwlock_wrlock(&http_lock);
	hash_release(http_table, group);
	pthread_rwlock_unlock(&http_lock);

	if (NULL != group->rule_json)
	{
		json_object_put(group->rule_json);
	}
	if (NULL != group->black_cmd_str)
	{
		SCFree(group->black_cmd_str);
	}
	if (NULL != group->url_str)
	{
		SCFree(group->url_str);
	}
	if (NULL != group->black_mime_str)
	{
		SCFree(group->black_mime_str);
	}
	if (NULL != group->black_keyword_str)
	{
		SCFree(group->black_keyword_str);
	}
	if (NULL != group->file_type_str)
	{
		SCFree(group->file_type_str);
	}
	timemgr_put(&group->tacl);

	list_for_each_entry_safe(item, item_n, &group->cmd_table, n_list)
	{
		SCLogInfo("del blackcmd item: %s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	list_for_each_entry_safe(item, item_n, &group->url_table, n_list)
	{
		SCLogInfo("del url item: %s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	list_for_each_entry_safe(item, item_n, &group->mime_table, n_list)
	{
		SCLogInfo("del mime item: %s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	list_for_each_entry_safe(item, item_n, &group->keyword_table, n_list)
	{
		SCLogInfo("del keyword item: %s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	list_for_each_entry_safe(item, item_n, &group->file_type_table, n_list)
	{
		SCLogInfo("del file type item: %s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	SCFree(group);
}

static struct http_rule_group *http_group_new(const char *name)
{
	struct http_rule_group *group = NULL;

	group = SCMalloc(sizeof(struct http_rule_group));
	if (NULL == group)
	{
		SCLogError("SCMalloc http_rule_group fail.\n");
		return NULL;
	}

	memset(group, 0, sizeof(*group));
	strncpy(group->groupname, name, NAME_LEN);

	INIT_LIST_HEAD(&group->url_table);
	INIT_LIST_HEAD(&group->cmd_table);
	INIT_LIST_HEAD(&group->mime_table);
	INIT_LIST_HEAD(&group->keyword_table);
	INIT_LIST_HEAD(&group->file_type_table);

	return group;
}

int http_check_rule_work_privilege(struct http_rule_group *group)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	if (1 == group->rule_work)
	{
		ret = -1;
	}
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

static int http_check_privilege(struct list_head *item_table, int rule_mode, char *items_str,
	const char *name)
{
	int ret = 0;
	int hit_it = 0;
	struct http_list_item *item = NULL;

	/* for all items */
	if (items_str[0] == '\0')
	{
		if (1 == rule_mode) /* whitelist */
			return -1;
		else
			return 0;  /* blacklist */
	}

	list_for_each_entry(item, item_table, n_list)
	{
		if (0 == strcasecmp(item->name, name))
		{
			hit_it = 1;
			break;
		}
	}

	if (((1 == hit_it) && (0 == rule_mode)) /* hit blacklist */
		|| ((0 == hit_it) && (1 == rule_mode))) /* not hit whitelist */
	{
		ret = -1;
	}
	return ret;
}

static int http_check_url_privilege(struct filter_header *hdr, struct list_head *item_table, int rule_mode, char *items_str,
	const char *name)
{
	int ret = 0;
	int hit_it = 0;
	struct http_list_item *item = NULL;
	char whole_url[1024] = { 0 };
	sprintf(whole_url, "http://%s:%d%s", hdr->svr->localip, hdr->svr->localport, name);

	/* for all items */
	if (items_str[0] == '\0')
	{
		if (1 == rule_mode) /* whitelist */
			return -1;
		else
			return 0;  /* blacklist */
	}

	list_for_each_entry(item, item_table, n_list)
	{
		if (NULL != strstr(whole_url, item->name))
		{
			hit_it = 1;
			break;
		}
	}

	if (((1 == hit_it) && (0 == rule_mode)) /* hit blacklist */
		|| ((0 == hit_it) && (1 == rule_mode))) /* not hit whitelist */
	{
		ret = -1;
	}
	return ret;
}

int http_check_rqst_head_privilege(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	/* check black cmd, 0 represents black */
	ret = http_check_privilege(&group->cmd_table, 0, group->black_cmd_str, head->method);
	if (-1 == ret)
	{
		SCLogInfo("hit head :black method.\n");
		goto done;
	}
	/* check url */
	ret = http_check_url_privilege(hdr, &group->url_table, group->url_rule_mode, group->url_str, head->url);
	if (-1 == ret)
	{
		SCLogInfo("hit head :black url or not white url.\n");
		goto done;
	}
	/* check head max length*/
	if (0 == group->length_rule_mode && group->max_http_head_len < head->head_len)
	{
		SCLogInfo("hit head :exceed head length.\n");
		ret = -1;
	}

done:
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

int http_check_resp_head_privilege(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	/* check mime, 0 represents black*/
	ret = http_check_privilege(&group->mime_table, 0, group->black_mime_str, head->mime);
	if (-1 == ret)
	{
		SCLogInfo("hit head :black mime.\n");
		goto done;
	}
	/* check head max length*/
	if (0 == group->length_rule_mode && group->max_http_head_len < head->head_len)
	{
		SCLogInfo("hit head :exceed head length.\n");
		ret = -1;
	}

done:
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

static char *keyword_convert(char *from_charset, const char *to_charset, char *inbuf, int inlen, char *outbuf, int outlen)
{
	iconv_t cd;

	char **pin = &inbuf;
	char **pout = &outbuf;

	if (NULL == to_charset)
	{
		return inbuf;
	}

	if (0 == strncasecmp(to_charset, UTF8, strlen(UTF8)))
	{
		return inbuf;
	}

	cd = iconv_open(to_charset, from_charset);
	if ((iconv_t)(-1) == cd)
	{
		perror("iconv_open");
		return NULL;
	}

	memset(outbuf, 0, outlen);

	if ((size_t)-1 == iconv(cd, pin, (size_t*)&inlen, pout, (size_t*)&outlen))
	{
		perror("iconv");
		return NULL;
	}

	iconv_close(cd);
	return outbuf;
}

int http_check_content_privilege(struct http_rule_group *group, const char *buf, const char *charset)
{
	if (NULL == group)
		return 0;

	int ret = 0;
	char *pos = NULL;
	char *keyword = NULL;
	char charset_out[OUT_LEN] = { 0 };
	struct http_list_item *item = NULL;
	pthread_rwlock_rdlock(&http_lock);
	if (NULL != group->black_keyword_str)
	{
		list_for_each_entry(item, &group->keyword_table, n_list)
		{
			if (item->name[0] != '\0')
			{
				keyword = keyword_convert(UTF8, charset, item->name, strlen(item->name), charset_out, OUT_LEN);
				if (NULL == keyword)
				{
					goto done;
				}
				pos = strcasestr(buf, keyword);
				if (NULL != pos)
				{
					SCLogInfo("hit content : black keyword.\n");
					ret = -1;
					goto done;
				}
			}
		}
	}

	if (0 == group->script_rule_mode)
	{
		pos = strstr(buf, SCRIPT);
		if (NULL != pos)
		{
			SCLogInfo("hit content : forbid script.\n");
			ret = -1;
			goto done;
		}
	}

	if (0 == group->applet_rule_mode)
	{
		pos = strstr(buf, APPLET);
		if (NULL != pos)
		{
			SCLogInfo("hit content : forbid applet.\n");
			ret = -1;
			goto done;
		}
	}

	if (0 == group->activex_rule_mode)
	{
		pos = strstr(buf, ACTIVEX);
		if (NULL != pos)
		{
			SCLogInfo("hit content : forbid activex.\n");
			ret = -1;
			goto done;
		}
	}

done:
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

int http_check_file_privilege(struct http_rule_group *group)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	if (0 == group->file_download_mode)
	{
		SCLogInfo("hit file download: prohibit download.\n");
		ret = -1;
	}
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

int http_check_file_type_privilege(struct filter_header *hdr, struct http_rule_group *group, char *file_type)
{
	if (NULL == group || NULL == file_type)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	/* check file type, 0 represents black*/
	ret = http_check_privilege(&group->file_type_table, 0, group->file_type_str, file_type);
	if (-1 == ret)
	{
		SCLogInfo("hit file download: black file type.\n");
	}
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

int http_check_file_length_privilege(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	if (0 == group->length_download_mode && group->max_download_file_len < head->content_len)
	{
		SCLogInfo("hit file download: exceed file length.\n");
		ret = -1;
	}
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

int http_check_file_virus_detection(struct http_rule_group *group)
{
	if (NULL == group)
		return 0;

	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	if (1 == group->virus_detection)
	{
		SCLogInfo("hit file download: need virus_detection.\n");
		ret = -1;
	}
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

void http_kill_virus_detection_process(char *filepath)
{
	FILE *fp_read = NULL;
	char buf[1024] = { 0 };
	pid_t pid;

	snprintf(buf, sizeof(buf), "ps -ef | grep testscan | grep %s |awk '{print $2}'", filepath);
	fp_read = popen(buf, "r");
	if (fp_read == NULL)
		return;
	memset(buf, 0, sizeof(buf));
	if (fgets(buf, sizeof(buf), fp_read) != NULL)
	{
		pid = atoi(buf);
		SCLogInfo("testscan pid: %d\n", pid);
		if (pid > 0)
			cmd_system_novty_arg("kill -9 %d", pid);
	}
}

static int http_virus_detection_timeout(struct thread *t)
{
	char *filepath = THREAD_ARG(t);
	SCLogInfo("virus_detection_timeout, filepath: %s\n", filepath);
	http_kill_virus_detection_process(filepath);
	return 0;
}

int http_file_virus_detection(char *filepath)
{
	FILE *fp_read = NULL;
	struct thread *timer = NULL;
	char buf[1024] = { 0 };

	snprintf(buf, sizeof(buf), "cd %s && ./testscan ./ %s", HTTP_VIRUS_DETECTION_TOOL_PATH, filepath);
	fp_read = popen(buf, "r");
	if (fp_read == NULL)
	{
		SCLogError("popen Failed\n");
		return -1;
	}

	timer = thread_add_timer(master, http_virus_detection_timeout, filepath, 60);

	while (fgets(buf, sizeof(buf), fp_read) != NULL)
	{
		SCLogInfo("buf: %s\n", buf);
		if (strstr(buf, "VirusName"))
		{
			thread_cancel(timer);
			http_kill_virus_detection_process(filepath);
			pclose(fp_read);
			fp_read = NULL;
			return -1;
		}
	}
	thread_cancel(timer);
	SCLogInfo("%s no virus\n", filepath);

	pclose(fp_read);
	return 0;
}

int http_check_effectime(struct http_rule_group *group)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	if (0 != check_time_privilege(&group->tacl))
	{
		SCLogInfo("hit effective time: prohibit access.\n");
		ret = -1;
	}
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

int http_check_user_num(struct filter_header *hdr, struct http_rule_group *group, struct http_filter *head)
{
	if (NULL == group)
		return 0;
	int ret = 0;
	pthread_rwlock_rdlock(&http_lock);
	if (0 == group->user_num_mode && group->max_user_access_num < head->user_num)
	{
		SCLogInfo("hit user num: exceed user_num.\n");
		ret = -1;
	}
	pthread_rwlock_unlock(&http_lock);
	return ret;
}

static int json_to_item_str(struct json_object *items_json, struct list_head *items_list_head, char **items_str)
{
	int idx = 0;
	const char *json_item_str = NULL;
	const char *json_item_one_str = NULL;
	struct http_list_item *item = NULL;
	struct http_list_item *item_n = NULL;

	json_item_str = json_object_to_json_string_ext(items_json, 0);
	SCLogInfo("add json_item_str:%s, old json_item_str:%s\n", json_item_str, *items_str);

	/* items_str never changed */
	if ((NULL != *items_str) && (0 == strcmp(*items_str, json_item_str)))
	{
		return 0;
	}

	/* clear items_str */
	if (NULL != *items_str)
	{
		SCFree(*items_str);
		*items_str = NULL;
	}

	/* add items_str */
	*items_str = SCStrdup(json_item_str);
	if (NULL == *items_str)
	{
		SCLogInfo("json_to_item_str: *items_str is NULL\n");
		return -1;
	}

	/* clear items_list */
	list_for_each_entry_safe(item, item_n, items_list_head, n_list)
	{
		SCLogInfo("del item: %s\n", item->name);
		SCFree(item->name);
		list_del(&item->n_list);
		SCFree(item);
	}

	/* add items_list */
	for (idx = 0; idx < json_object_array_length(items_json); idx++)
	{
		json_item_one_str = json_object_get_string(json_object_array_get_idx(items_json, idx));
		item = SCMalloc(sizeof(struct http_list_item));
		if (NULL == item)
		{
			SCLogInfo("json_to_item_str: SCMalloc error\n");
			return -1;
		}
		item->name = SCStrdup(json_item_one_str);
		list_add(&item->n_list, items_list_head);
		SCLogInfo("add item: %s\n", item->name);
	}

	return 0;
}


static int http_parse_json_head(struct http_rule_group *group)
{
	int ret = 0;
	struct json_object *head_json = NULL;
	struct json_object *head_url_val_json = NULL;

	/* get head json */
	head_json = json_object_object_get(group->rule_json, "head");
	if (NULL == head_json)
	{
		SCLogInfo("http: there is no 'head' rule");
		return 0;
	}

	/* get head detail json */
	json_object_object_foreach(head_json, key, val)
	{
		if (0 == strcmp(key, "black_cmd"))
		{
			ret = json_to_item_str(val, &group->cmd_table, &group->black_cmd_str);
			if (0 != ret)
				break;
		}
		else if (0 == strcmp(key, "url"))
		{
			group->url_rule_mode = atoi(json_object_get_string(json_object_object_get(val, "mode")));
			head_url_val_json = json_object_object_get(val, "value");
			ret = json_to_item_str(head_url_val_json, &group->url_table, &group->url_str);

			if (0 != ret)
				break;
		}
		else if (0 == strcmp(key, "black_mime"))
		{
			ret = json_to_item_str(val, &group->mime_table, &group->black_mime_str);
			if (0 != ret)
				break;
		}
		else if (0 == strcmp(key, "size"))
		{
			group->length_rule_mode = atoi(json_object_get_string(json_object_object_get(val, "mode")));
			group->max_http_head_len = atoi(json_object_get_string(json_object_object_get(val, "value")));
		}
		else
		{
		}
	}

	return 0;
}

static int http_parse_json_content(struct http_rule_group *group)
{
	int ret = 0;
	struct json_object *content_json = NULL;

	/* get content json */
	content_json = json_object_object_get(group->rule_json, "content");
	if (NULL == content_json)
	{
		SCLogInfo("http: there is no 'content' rule");
		return 0;
	}

	/* get content detail json */
	json_object_object_foreach(content_json, key, val)
	{
		if (0 == strcmp(key, "black_keyword"))
		{
			ret = json_to_item_str(val, &group->keyword_table, &group->black_keyword_str);
			if (0 != ret)
				break;
		}
		else if (0 == strcmp(key, "script"))
		{
			group->script_rule_mode = atoi(json_object_get_string(val));
		}
		else if (0 == strcmp(key, "applet"))
		{
			group->applet_rule_mode = atoi(json_object_get_string(val));
		}
		else if (0 == strcmp(key, "activex"))
		{
			group->activex_rule_mode = atoi(json_object_get_string(val));
		}
		else
		{
		}
	}
	return ret;
}

static int http_parse_json_file(struct http_rule_group *group)
{
	int ret = 0;
	struct json_object *file_json = NULL;

	/* get content json */
	file_json = json_object_object_get(group->rule_json, "file");
	if (NULL == file_json)
	{
		SCLogInfo("http: there is no 'file' rule");
		return 0;
	}

	/* get content detail json */
	json_object_object_foreach(file_json, key, val)
	{
		if (0 == strcmp(key, "type"))
		{
			ret = json_to_item_str(val, &group->file_type_table, &group->file_type_str);
			if (0 != ret)
				break;
		}
		else if (0 == strcmp(key, "mode"))
		{
			group->file_download_mode = atoi(json_object_get_string(val));
		}
		else if (0 == strcmp(key, "size"))
		{
			group->length_download_mode = atoi(json_object_get_string(json_object_object_get(val, "mode")));
			group->max_download_file_len = 1024 * 1024 * atoi(json_object_get_string(json_object_object_get(val, "value")));
		}
		else if (0 == strcmp(key, "virus_detection"))
		{
			group->virus_detection = atoi(json_object_get_string(val));
		}
		else
		{
		}
	}
	return ret;
}

static int http_parse_json_effectime(struct http_rule_group *group)
{
	struct json_object *time_json = NULL;
	char *effectime = NULL;

	/* get time json */
	time_json = json_object_object_get(group->rule_json, "timespan");
	if (NULL == time_json)
	{
		SCLogInfo("http: there is no 'timespan' rule");
		return 0;
	}
	/* get time detail json */
	json_object_object_foreach(time_json, key, val)
	{
		if (0 == strcmp(key, "effectime"))
		{
			effectime = json_object_get_string(val);
			if (NULL == effectime)
				return 0;
			timemgr_put(&group->tacl);/* Release reference count */
			strncpy(group->effectime, effectime, strlen(effectime) + 1);
			SCLogInfo("add effectime item: %s\n", group->effectime);
			timemgr_get(&group->tacl, group->effectime);
		}
		else if (0 == strcmp(key, "user"))
		{
			group->user_num_mode = atoi(json_object_get_string(json_object_object_get(val, "mode")));
			group->max_user_access_num = atoi(json_object_get_string(json_object_object_get(val, "value")));
		}
		else
		{
		}
	}

	return 0;
}

/*
{
	"groupName":"G1",
	"rule_work":
		 "1",
	"head": {
		"black_cmd": ["get", "post"],
		"url": {"mode": "0", "value":  ["www.baidu.com","www.163.com"] },
		"black_mime": ["text", "radio"],
		"size": {"mode":"0", "value":"2000"}
	}，
	"content"：{
		"black_keyword":["danger","voilence"],
		"script":"0",
		"applet":"0",
		"activex":"0"
	},
	"file":{
		"mode":"0",
		"size":"1024",
		"type":[".tar, exe"],
		"virus_detection":"0"
	},
	"timespan":{
	"effectime":"afternoon",
	"user":{"mode":"0", "value":"2000"}
	}
}
*/
DEFUN(gap_ctl_http_add,
	gap_ctl_http_add_cmd,
	"protocol-http add rule .JSON",
	"http command\n"
	"add http rule\n"
	"rule\n"
	"json string,eg:{}\n")
{
	char *groupname = NULL;
	char *rule_json_str = NULL;
	struct json_object *jobj = NULL;
	struct http_rule_group *group = NULL;

	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	pthread_rwlock_wrlock(&http_lock);
	rule_json_str = argv_concat(argv, argc, 0);
	jobj = json_tokener_parse(rule_json_str);
	if (NULL == jobj)
	{
		XFREE(MTYPE_TMP, rule_json_str);
		vty_result(ERR_CODE_JSONERR, ERR_CODE_JSONERR_DESC);
		goto done;
	}

	groupname = json_object_get_string(json_object_object_get(jobj, "groupName"));
	group = get_protocol_rule(groupname, SVR_ID_HTTP);
	if (NULL == group)
	{
		group = http_group_new(groupname);
		if (NULL == group)
		{
			vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
			goto done;
		}
		group->group = get_group_by_name(groupname);
		http_add_rule_group(group);
	}

	/* add http group */
	if (NULL != group->rule_json)
	{
		json_object_put(group->rule_json);
	}
	group->rule_json = jobj;

	/* add rule work */
	group->rule_work = atoi(json_object_get_string(json_object_object_get(group->rule_json, "rule_work")));

	/* add effective time */
	if (0 != http_parse_json_effectime(group))
	{
		goto done;
	}
	/* add http group head detail */
	if (0 != http_parse_json_head(group))
	{
		goto done;
	}
	/* add http group content detail */
	if (0 != http_parse_json_content(group))
	{
		goto done;
	}
	/* add http group file detail */
	if (0 != http_parse_json_file(group))
	{
		goto done;
	}
	/* set protocol for group rule */
	if (0 != set_protocol_rule(groupname, SVR_ID_HTTP, group))
	{
		goto done;
	}

done:
	XFREE(MTYPE_TMP, rule_json_str);
	pthread_rwlock_unlock(&http_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_http_add,
	gap_ctl_http_add_outer_cmd,
	"outer protocol-http add rule .JSON",
	"outer machine\n"
	"http command\n"
	"add http rule\n"
	"rule\n"
	"json string,eg:{}\n");

DEFUN(gap_ctl_http_del,
	gap_ctl_http_del_cmd,
	"protocol-http delete groupname NAME",
	"http command\n"
	"delete http rule\n"
	"groupname\n"
	"group name\n")
{
	struct http_rule_group *group = NULL;
	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter *)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __func__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	pthread_rwlock_rdlock(&http_lock);
	group = get_protocol_rule(argv[0], SVR_ID_HTTP);
	pthread_rwlock_unlock(&http_lock);

	if (NULL != group)
	{
		http_del_rule_group(group);
	}
	else
	{
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_http_del,
	gap_ctl_http_del_outer_cmd,
	"outer protocol-http delete groupname NAME",
	"outer machine\n"
	"http command\n"
	"delete http rule\n"
	"groupname\n"
	"group name\n");

DEFUN(gap_ctl_http_view,
	gap_ctl_http_view_cmd,
	"show protocol-http {groupname NAME}",
	SHOW_STR
	"http rule\n"
	"groupname\n"
	"name\n"
)
{
	struct http_rule_group *group = NULL;
	const char *groupname = argv[0];
	SHOW_CMD_RUN();

	pthread_rwlock_rdlock(&http_lock);
	if (NULL != groupname)
	{
		group = get_protocol_rule(groupname, SVR_ID_HTTP);
		if (NULL != group)
		{
			if (NULL != group->rule_json)
			{
				vty_out(vty, "%s%s", JSON_FORMAT_STR(group->rule_json), VTY_NEWLINE);
			}
		}
	}
	else
	{
		hash_iterate(http_table, http_show_pvty, vty);
	}
	pthread_rwlock_unlock(&http_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_http_view,
	gap_ctl_http_view_o_cmd,
	"show outer protocol-http {groupname NAME}",
	SHOW_STR
	"outer machine\n"
	"show http rule\n"
	"groupname\n"
	"group name\n");

static struct cmd_node http_node =
{
	.node = PROTO_HTTP_AUDIT,
	.prompt = "",
	.vtysh = 1
};

int http_config_write(struct vty *vty)
{
	pthread_rwlock_rdlock(&http_lock);
	hash_iterate(http_table, http_write_pvty, vty);
	pthread_rwlock_unlock(&http_lock);
	return 0;
}

static void http_conf_cmd_init(void)
{
	install_element(VIEW_NODE, &gap_ctl_http_view_cmd);
	install_element(VIEW_NODE, &gap_ctl_http_view_o_cmd);

	install_element(ENABLE_NODE, &gap_ctl_http_view_cmd);
	install_element(ENABLE_NODE, &gap_ctl_http_view_o_cmd);

	install_element(CONFIG_NODE, &gap_ctl_http_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_http_del_cmd);

	install_element(CONFIG_NODE, &gap_ctl_http_add_outer_cmd);
	install_element(CONFIG_NODE, &gap_ctl_http_del_outer_cmd);

	install_node(&http_node, http_config_write);
}

void http_cmd_init(void)
{
	pthread_rwlock_init(&http_lock, NULL);
	http_table = hash_create(http_hashkey, http_hashcmp);
	http_conf_cmd_init();
	register_delete_proto_rule_callback(SVR_ID_HTTP, http_del_rule_group);
}

void http_cmd_exit(void)
{
	pthread_rwlock_wrlock(&http_lock);
	hash_clean(http_table, http_del_rule_group);
	hash_free(http_table);
	pthread_rwlock_unlock(&http_lock);
}
