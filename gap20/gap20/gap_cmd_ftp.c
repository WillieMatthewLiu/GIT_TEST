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
#include "parser_ftp.h"
#include "gap_cmd_ftp.h"
#include "gap_cmd_group.h"
#include "svrid.h"

#include <iconv.h>

extern struct thread_master *master;

/*
 *	Hash table: for user lookups
 */
static struct hash * ftp_group_hash;
pthread_rwlock_t ftp_lock;

/* ftp cmds big name list */
static char *cmds_big_list[] = {
	[FTP_CMD_DELE] = "delete",
	[FTP_CMD_NLST] = "ls",
	[FTP_CMD_LIST] = "ls",
	[FTP_CMD_CWD] = "cd",
	[FTP_CMD_XCWD] = "cd",
	[FTP_CMD_RETR] = "get",
	[FTP_CMD_STOR] = "put",
	[FTP_CMD_XPWD] = "pwd",
	[FTP_CMD_XMKD] = "mkdir",
	[FTP_CMD_RNFR] = "rename",
	[FTP_CMD_RNTO] = "rename",
	[FTP_CMD_XRMD] = "rmdir",
	[FTP_CMD_APPE] = "append"
};

static unsigned int ftp_hash_key(void *data)
{
	return data;
}

static int ftp_group_hash_cmp(const void *data1, const void *data2)
{
	return data1 == data2;
}

static int ftp_item_hash_cmp(const void *data1, const void *data2)
{
	const char *tmp1 = (const char *)data1;
	const char *tmp2 = (const char *)data2;

	return !strcmp(tmp1, tmp2);
}

static void * ftp_item_hash_alloc_func(void *data)
{
	char *tmp = (char *)data;
	return (void *)SCStrdup(tmp);
}

static void ftp_item_hash_free_func(void *data)
{
	SCLogInfo("free item: %s\n", (char *)data);
	SCFree(data);
}

static struct ftp_rule_group *ftp_add_rule_group(struct ftp_rule_group *group)
{
	return (struct ftp_rule_group *)hash_get(ftp_group_hash, (void *)group, hash_alloc_intern);
}

static void ftp_del_rule_group(struct ftp_rule_group *group)
{
	hash_release(ftp_group_hash, group);

	if (group->json_rule)
		json_object_put(group->json_rule);
	if (group->banner_info)
		SCFree(group->banner_info);
	if (group->users_str)
		SCFree(group->users_str);
	if (group->cmds_str)
		SCFree(group->cmds_str);
	if (group->up_types_str)
		SCFree(group->up_types_str);
	if (group->down_types_str)
		SCFree(group->down_types_str);

	if (group->users)
	{
		hash_clean(group->users, ftp_item_hash_free_func);
		hash_free(group->users);
	}
	if (group->cmds)
	{
		hash_clean(group->cmds, ftp_item_hash_free_func);
		hash_free(group->cmds);
	}
	if (group->up_types)
	{
		hash_clean(group->up_types, ftp_item_hash_free_func);
		hash_free(group->up_types);
	}
	if (group->down_types)
	{
		hash_clean(group->down_types, ftp_item_hash_free_func);
		hash_free(group->down_types);
	}

	SCFree(group);
}

void ftp_del_rule_group_extern(void *protocol_rule)
{
	struct ftp_rule_group *group = (struct ftp_rule_group *)protocol_rule;
	if (!group)
		return;
	pthread_rwlock_wrlock(&ftp_lock);
	ftp_del_rule_group(group);
	pthread_rwlock_unlock(&ftp_lock);
}

static struct ftp_rule_group * ftp_group_new(const char *name)
{
	struct ftp_rule_group *group = SCMalloc(sizeof(*group));

	if (!group)
		return NULL;

	memset(group, 0, sizeof(*group));
	strncpy(group->groupname, name, sizeof(group->groupname) - 1);

	group->users = hash_create(string_hash_make, ftp_item_hash_cmp);
	group->cmds = hash_create(string_hash_make, ftp_item_hash_cmp);
	group->up_types = hash_create(string_hash_make, ftp_item_hash_cmp);
	group->down_types = hash_create(string_hash_make, ftp_item_hash_cmp);

	return group;
}

static int ftp_check_privilege(struct hash *item_hash, int rule_mode, char *items_str,
	const char *name)
{
	int ret = 0;
	int hit_it = 0;

	/* for all items */
	if (!items_str)
	{
		if (rule_mode) /* whitelist */
			return 0;
		else
			return -1;  /* blacklist */
	}

	if (hash_lookup(item_hash, (void *)name))
		hit_it = 1;

	if ((hit_it && !rule_mode) /* hit blacklist */
		|| (!hit_it && rule_mode)) /* not hit whitelist */
		ret = -1;

	SCLogInfo("hit_it: %d, ret: %d\n", hit_it, ret);
	return ret;
}

int ftp_check_user_privilege(struct ftp_rule_group *group, const char *user)
{
	int ret = 0;

	pthread_rwlock_rdlock(&ftp_lock);
	ret = ftp_check_privilege(group->users, group->user_rule_mode, group->users_str, user);
	pthread_rwlock_unlock(&ftp_lock);
	return ret;
}

static int get_ftp_cmd_index(const char *cmd)
{
	int index;
	if (strcmp(cmd, "DELE") == 0) {
		index = FTP_CMD_DELE;
	}
	else if (strcmp(cmd, "NLST") == 0) {
		index = FTP_CMD_NLST;
	}
	else if (strcmp(cmd, "LIST") == 0) {
		index = FTP_CMD_LIST;
	}
	else if (strcmp(cmd, "CWD") == 0) {
		index = FTP_CMD_CWD;
	}
	else if (strcmp(cmd, "XCWD") == 0) {
		index = FTP_CMD_XCWD;
	}
	else if (strcmp(cmd, "RETR") == 0) {
		index = FTP_CMD_RETR;
	}
	else if (strcmp(cmd, "STOR") == 0) {
		index = FTP_CMD_STOR;
	}
	else if (strcmp(cmd, "XPWD") == 0) {
		index = FTP_CMD_XPWD;
	}
	else if (strcmp(cmd, "PWD") == 0) {
		index = FTP_CMD_XPWD;
	}
	else if (strcmp(cmd, "XMKD") == 0) {
		index = FTP_CMD_XMKD;
	}
	else if (strcmp(cmd, "MKD") == 0) {
		index = FTP_CMD_XMKD;
	}
	else if (strcmp(cmd, "RNFR") == 0) {
		index = FTP_CMD_RNFR;
	}
	else if (strcmp(cmd, "RNTO") == 0) {
		index = FTP_CMD_RNTO;
	}
	else if (strcmp(cmd, "XRMD") == 0) {
		index = FTP_CMD_XRMD;
	}
	else if (strcmp(cmd, "RMD") == 0) {
		index = FTP_CMD_XRMD;
	}
	else if (strcmp(cmd, "APPE") == 0) {
		index = FTP_CMD_APPE;
	}
	else {
		index = FTP_CMD_OTHER;
	}

	return index;
}

int ftp_check_cmd_privilege(struct ftp_rule_group *group, const char *cmd)
{
	int ret = 0;
	int hit_it = 0;
	int cmd_index;

	/* check whether cmd is in cmds_big_list, if cmd is not in, pass this cmd anyway.
	*/
	cmd_index = get_ftp_cmd_index(cmd);
	SCLogInfo("cmd: %s, cmd_index: %d\n", cmd, cmd_index);
	if (cmd_index == FTP_CMD_OTHER)
		return 0;

	pthread_rwlock_rdlock(&ftp_lock);
	/* cmd list is null */
	if (!group->cmds_str)
	{
		if (group->cmd_rule_mode) /* whitelist */
		{
			ret = -1;
			goto out;
		}
		else
		{
			ret = 0;  /* blacklist */
			goto out;
		}
	}

	if (hash_lookup(group->cmds, cmds_big_list[cmd_index]))
		hit_it = 1;

	if ((hit_it && !group->cmd_rule_mode) /* hit blacklist */
		|| (!hit_it && group->cmd_rule_mode)) /* not hit whitelist */
		ret = -1;

out:
	if (group)
		SCLogInfo("rule_mode: %d\n", group->cmd_rule_mode);
	SCLogInfo("cmd: %s, hit_it: %d, ret: %d\n", cmds_big_list[cmd_index], hit_it, ret);
	pthread_rwlock_unlock(&ftp_lock);
	return ret;
}

int ftp_check_upfile_type_privilege(struct ftp_rule_group *group, const char *file_type)
{
	int ret = 0;

	pthread_rwlock_rdlock(&ftp_lock);
	ret = ftp_check_privilege(group->up_types, group->up_rule_mode, group->up_types_str, file_type);
	pthread_rwlock_unlock(&ftp_lock);
	return ret;
}

int ftp_check_downfile_type_privilege(struct ftp_rule_group *group, const char *file_type)
{
	int ret = 0;

	pthread_rwlock_rdlock(&ftp_lock);
	ret = ftp_check_privilege(group->down_types, group->down_rule_mode, group->down_types_str, file_type);
	pthread_rwlock_unlock(&ftp_lock);
	return ret;
}

uint64_t ftp_get_max_upfile_length(struct ftp_rule_group *group)
{
	uint64_t length = 0;
	pthread_rwlock_rdlock(&ftp_lock);
	length = group->max_up_file_len;
	pthread_rwlock_unlock(&ftp_lock);
	return length;
}

uint64_t ftp_get_max_downfile_length(struct ftp_rule_group *group)
{
	uint64_t length = 0;
	pthread_rwlock_rdlock(&ftp_lock);
	length = group->max_down_file_len;
	pthread_rwlock_unlock(&ftp_lock);
	return length;
}

int ftp_check_upfile_virus_detection(struct ftp_rule_group *group)
{
	int ret = 0;

	pthread_rwlock_rdlock(&ftp_lock);
	ret = group->up_virus_detection;
	pthread_rwlock_unlock(&ftp_lock);
	return ret;
}

int ftp_check_downfile_virus_detection(struct ftp_rule_group *group)
{
	int ret = 0;

	pthread_rwlock_rdlock(&ftp_lock);
	ret = group->down_virus_detection;
	pthread_rwlock_unlock(&ftp_lock);
	return ret;
}

int ftp_get_banner_info(struct ftp_rule_group *group, char *buf, int size)
{
	int ret = 0, len;

	pthread_rwlock_rdlock(&ftp_lock);
	if (group->rule_work && group->banner_info)
	{
		len = snprintf(buf, size - 2, "%s", group->banner_info);
		buf[len] = '\r';
		buf[len + 1] = '\n';
		ret = 1;
	}
	pthread_rwlock_unlock(&ftp_lock);
	return ret;
}

void kill_virus_detection_process(char *filepath)
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

int virus_detection_timeout(struct thread *t)
{
	char *filepath = THREAD_ARG(t);
	SCLogInfo("virus_detection_timeout, filepath: %s\n", filepath);
	kill_virus_detection_process(filepath);
	return 0;
}

int ftp_file_virus_detection(char *filepath)
{
	FILE *fp_read = NULL;
	struct thread *timer = NULL;
	char buf[1024] = { 0 };

	snprintf(buf, sizeof(buf), "cd %s && ./testscan ./ %s", VIRUS_DETECTION_TOOL_PATH, filepath);
	fp_read = popen(buf, "r");
	if (fp_read == NULL)
	{
		SCLogError("popen Failed\n");
		return -1;
	}

	timer = thread_add_timer(master, virus_detection_timeout, filepath, 60);

	while (fgets(buf, sizeof(buf), fp_read) != NULL)
	{
		SCLogInfo("buf: %s\n", buf);
		if (strstr(buf, "VirusName"))
		{
			thread_cancel(timer);
			kill_virus_detection_process(filepath);
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

static int translate_items(struct json_object * json_item, struct hash *items_hash, char **items_str)
{
	int i, ret = 0;
	const char *tmp = NULL;
	const char *tmp_str;

	tmp_str = json_object_to_json_string_ext(json_item, 0);
	SCLogInfo("tmp_str: %s\n", tmp_str);
	/* items_str never changed */
	if (*items_str && !strcmp(*items_str, tmp_str))
		return 0;

	if (*items_str)
	{
		SCFree(*items_str);
		*items_str = NULL;
	}

	/* clear list */
	hash_clean(items_hash, ftp_item_hash_free_func);

	/* for all items */
	if (strchr(tmp_str, '*'))
		return 0;

	*items_str = SCStrdup(tmp_str);
	if (!*items_str)
		return -1;

	for (i = 0; i < json_object_array_length(json_item); i++)
	{
		tmp = json_object_get_string(json_object_array_get_idx(json_item, i));
		if (hash_get(items_hash, (void *)tmp, ftp_item_hash_alloc_func) == NULL)
		{
			ret = -1;
			break;
		}
		SCLogInfo("add item: %s\n", tmp);
	}

	return ret;
}

static int ftp_parse_json_user(struct ftp_rule_group *group)
{
	int ret = 0;
	struct json_object *json_user = json_object_object_get(group->json_rule, "user");

	if (!json_user)
		return 0;

	json_object_object_foreach(json_user, key, val)
	{
		if (!strcmp(key, "mode"))
		{
			group->user_rule_mode = atoi(json_object_get_string(val));
		}
		else if (!strcmp(key, "value"))
		{
			ret = translate_items(val, group->users, &group->users_str);
			if (ret)
				break;
		}
	}

	return ret;
}

static int ftp_parse_json_cmd(struct ftp_rule_group *group)
{
	int ret = 0;
	struct json_object *json_cmd = json_object_object_get(group->json_rule, "command");

	if (!json_cmd)
		return 0;

	json_object_object_foreach(json_cmd, key, val)
	{
		if (!strcmp(key, "mode"))
		{
			group->cmd_rule_mode = atoi(json_object_get_string(val));
		}
		else if (!strcmp(key, "value"))
		{
			ret = translate_items(val, group->cmds, &group->cmds_str);
			if (ret)
				break;
		}
	}

	return ret;
}

int utf8_to_ascii(char *inbuf, int *inlen, char *outbuf, int *outlen)
{
	/* 目的编码, TRANSLIT：遇到无法转换的字符就找相近字符替换GB
	 *           IGNORE ：遇到无法转换字符跳过*/
	char *encTo = "ascii";
	/* 源编码 */
	char *encFrom = "utf-8";

	/* 获得转换句柄
	 *@param encTo 目标编码方式
	 *@param encFrom 源编码方式
	 *
	 * */
	iconv_t cd = iconv_open(encTo, encFrom);
	if (cd == (iconv_t) - 1)
	{
		perror("iconv_open");
		return 0;
	}

	/* 需要转换的字符串 */
	printf("inbuf=%s\n", inbuf);

	/* 打印需要转换的字符串的长度 */
	printf("inlen=%d\n", *inlen);

	/* 由于iconv()函数会修改指针，所以要保存源指针 */
	char *tmpin = inbuf;
	char *tmpout = outbuf;
	int insize = *inlen;
	int outsize = *outlen;

	/* 进行转换
	 *@param cd iconv_open()产生的句柄
	 *@param srcstart 需要转换的字符串
	 *@param inlen 存放还有多少字符没有转换
	 *@param tempoutbuf 存放转换后的字符串
	 *@param outlen 存放转换后,tempoutbuf剩余的空间
	 *
	 * */
	int nReturn = 0;
	
	size_t ret = iconv(cd, &tmpin, inlen, &tmpout, outlen);
	if (ret == -1)
	{
		perror("iconv");
		*inlen = insize;
		*outlen = strlen(outbuf);
		nReturn = (*outlen);
	}
	else
	{
		nReturn = outsize - (*outlen);
	}

	/* 存放转换后的字符串 */
	printf("outbuf=%s\n", outbuf);

	//存放转换后outbuf剩余的空间
	printf("outlen=%d\n", *outlen);

	int i = 0;
	for (i = 0; i < nReturn; i++)
	{
		printf("%x\n", outbuf[i]);
	}

	/* 关闭句柄 */
	iconv_close(cd);
	
	*outlen = nReturn;

	return nReturn;
}

//十六进制字符串转换为字节流
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{
	short i;
	unsigned char highByte, lowByte;
    
	for (i = 0; i < sourceLen; i += 2)
	{
		highByte = toupper(source[i]);
		lowByte  = toupper(source[i + 1]);


		if (highByte > 0x39)
			highByte -= 0x37;
		else
			highByte -= 0x30;


		if (lowByte > 0x39)
			lowByte -= 0x37;
		else
			lowByte -= 0x30;


		dest[i / 2] = (highByte << 4) | lowByte;
	}
	return ;
}

static int ftp_parse_json_keyword_info(struct ftp_rule_group *group)
{
	int i = 0;
	const char* pTmp = NULL;
	struct json_object *json_keyword = json_object_object_get(group->json_rule, "keyWord");
	
	group->nKeyCount = 0;
	memset(&group->nKeyLength, 0, sizeof(group->nKeyLength));
	memset(group->chKeyWord, 0, sizeof(group->chKeyWord));
	 
	if (!json_keyword)
	{
		return 0;
	}
	
	char chKeyWord[40] = { 0 };
	
	group->nKeyCount = json_object_array_length(json_keyword);
	for (i = 0; i < group->nKeyCount; i++)
	{
		pTmp = json_object_get_string(json_object_array_get_idx(json_keyword, i));

		if (pTmp[0] == '%')
		{
			pTmp++;
			memset(chKeyWord, 0, sizeof(chKeyWord));
			
			HexStrToByte(pTmp, chKeyWord, strlen(pTmp));	
			
			group->nKeyLength[i] = strlen(chKeyWord);
			strncpy(&group->chKeyWord[i * 40], chKeyWord, group->nKeyLength[i]);	
		}
		else
		{
			group->nKeyLength[i] = strlen(pTmp);
			strncpy(&group->chKeyWord[i * 40], pTmp, group->nKeyLength[i]);	
		}
		
		printf("KeyWord = %s\n", &group->chKeyWord[i * 40]);
	}

	/*int k = 0;
	int nInDataLen = 0;
	int nOutDataLen = 0;
	
	char chInBuffer[40] = { 0 };
	char chOutBuffer[40] = { 0 };
	int  nBufferLen = sizeof(chInBuffer);
	
	group->nKeyCount = json_object_array_length(json_keyword);
	for (i = 0; i < group->nKeyCount; i++)
	{
		pTmp = json_object_get_string(json_object_array_get_idx(json_keyword, i));
		strncpy(&group ->chKeyWord[k * 40], pTmp, 40);
		k++;

		nInDataLen = strlen(pTmp);
		nOutDataLen = nBufferLen;
		
		memset(chInBuffer, 0, nBufferLen);
		memset(chOutBuffer, 0, nBufferLen);
		
		strncpy(chInBuffer, pTmp, 40);
		
		if (utf8_to_ascii(chInBuffer, &nInDataLen, chOutBuffer, &nOutDataLen))
		{			
			if (nInDataLen != nOutDataLen)
			{
				strncpy(&group->chKeyWord[k * 40], chOutBuffer, nOutDataLen);
				k++;				
			}
		}
	}*/
	
	return i;		
}

static int ftp_parse_json_upfile(struct ftp_rule_group *group)
{
	int ret = 0;
	const char *tmp = NULL;
	struct json_object *json_upfile = json_object_object_get(group->json_rule, "upfile");

	if (!json_upfile)
		return 0;

	json_object_object_foreach(json_upfile, key, val)
	{
		if (!strcmp(key, "mode"))
		{
			group->up_rule_mode = atoi(json_object_get_string(val));
		}
		else if (!strcmp(key, "value"))
		{
			int i;
			struct json_object *value_obj = json_object_new_array();
			for (i = 0; i < json_object_array_length(val); i++)
			{
				tmp = json_object_get_string(json_object_array_get_idx(val, i));
				if (tmp[0] != '.' && tmp[0] != '*')
					continue;
				json_object_array_add(value_obj, json_object_new_string(tmp));
			}
			ret = translate_items(value_obj, group->up_types, &group->up_types_str);
			json_object_put(value_obj);
			if (ret)
				break;
		}
		else if (!strcmp(key, "max_filelen"))
		{
			tmp = json_object_get_string(val);
			group->max_up_file_len = atoi(tmp) * 1024 * 1024;
		}
		else if (!strcmp(key, "virus_detection"))
		{
			group->up_virus_detection = atoi(json_object_get_string(val));
		}
	}

	return ret;
}

static int ftp_parse_json_downfile(struct ftp_rule_group *group)
{
	int ret = 0;
	const char *tmp = NULL;
	struct json_object *json_downfile = json_object_object_get(group->json_rule, "downfile");

	if (!json_downfile)
		return 0;

	json_object_object_foreach(json_downfile, key, val)
	{
		if (!strcmp(key, "mode"))
		{
			group->down_rule_mode = atoi(json_object_get_string(val));
		}
		else if (!strcmp(key, "value"))
		{
			int i;
			struct json_object *value_obj = json_object_new_array();
			for (i = 0; i < json_object_array_length(val); i++)
			{
				tmp = json_object_get_string(json_object_array_get_idx(val, i));
				if (tmp[0] != '.' && tmp[0] != '*')
					continue;
				json_object_array_add(value_obj, json_object_new_string(tmp));
			}

			ret = translate_items(value_obj, group->down_types, &group->down_types_str);
			json_object_put(value_obj);
			if (ret)
				break;
		}
		else if (!strcmp(key, "max_filelen"))
		{
			tmp = json_object_get_string(val);
			group->max_down_file_len = atoi(tmp) * 1024 * 1024;
		}
		else if (!strcmp(key, "virus_detection"))
		{
			group->down_virus_detection = atoi(json_object_get_string(val));
		}
	}

	return ret;
}

static int ftp_parse_json_banner_info(struct ftp_rule_group *group)
{
	struct json_object *json_banner = json_object_object_get(group->json_rule, "banner");
	const char *banner_info = json_object_get_string(json_banner);

	if (!json_banner)
		return 0;

	banner_info = json_object_get_string(json_banner);
	SCLogInfo("banner_info: %s\n", banner_info);
	if (group->banner_info)
	{
		SCFree(group->banner_info);
		group->banner_info = NULL;
	}

	if (banner_info && strlen(banner_info))
		group->banner_info = SCStrdup(banner_info);

	return 0;
}

static void ftp_show_group_iterate(struct hash_backet *hb, void *arg)
{
	struct vty *vty = (struct vty *)arg;
	struct ftp_rule_group *group = (struct ftp_rule_group *)hb->data;

	vty_out(vty, "%s %s%s", group->groupname,
		json_object_to_json_string_ext(group->json_rule, 0), VTY_NEWLINE);
}

static void ftp_config_write_iterate(struct hash_backet *hb, void *arg)
{
	struct vty *vty = (struct vty *)arg;
	struct ftp_rule_group *group = (struct ftp_rule_group *)hb->data;

	vty_out(vty, "protocol-ftp add groupname %s rule %s%s", group->groupname,
		json_object_to_json_string_ext(group->json_rule, 0), VTY_NEWLINE);
}

int ftp_config_write(struct vty *vty)
{
	pthread_rwlock_rdlock(&ftp_lock);
	hash_iterate(ftp_group_hash, ftp_config_write_iterate, vty);
	pthread_rwlock_unlock(&ftp_lock);
	return 0;
}

/************************************************************************************************
1.简介：   在内存地址串1中查找内存地址串2第第一次出现的位置
2.参数：   str1 内存地址串1
		   n1   内存地址串1的长度
		   str2 内存地址串2
		   n2   内存地址串2的长度
3.返回值:  返回内存地址串2在内存地址串1中第一次出现的地址，或NULL未查找到
************************************************************************************************/
char* memstr(const char* str1, int n1, const char* str2, int n2)
{
	if (n1 < n2)
	{
		return NULL;
	}
	if (str2 == NULL)
	{
		return NULL;
	}

	int i = 0;
	int j = 0;

	char* s1 = NULL;
	char* s2 = NULL;
	char* cp = (char*)str1;

	for (; i < n1; i++)
	{
		s1 = cp;
		s2 = (char*)str2;

		while (*s1 == *s2)
		{
			s1++;
			s2++;
			j++;

			if (j == n2)
			{
				return cp;
			}
			if (*s2 == NULL)
			{
				return cp;
			}
		}

		cp++; 
		j = 0;
	}

	return NULL;
}

int ftp_check_keyword(struct ftp_rule_group* pGroup, const char* pData, int nDataLen)
{
	if (pGroup->rule_work == 0)
	{
		//规则不启动
		return 0;
	}
	
	int i = 0;
	for (; i < pGroup->nKeyCount; i++)
	{		
		if (memstr(pData, nDataLen, &pGroup->chKeyWord[i * 40], pGroup->nKeyLength[i]) != NULL)
		{
			//找到关键字，退出
			return i + 1;
		}
	}
	
	return 0;
}

DEFUN(gap_ctl_ftp_add,
	gap_ctl_ftp_add_cmd,
	"protocol-ftp add groupname NAME rule .JSON",
	"ftp command\n"
	"add ftp rule\n"
	"groupname\n"
	"name string\n"
	"rule\n"
	"json string, format: {'rule_work':'1','user':{'mode':'1','value':['xxx','xdli']},'command':{'mode':'0','value':['*']},"
	"'upfile':{'mode':'0','value':['.txt','.avi'],'max_filelen':'400','virus_detection':'1'},"
	"'downfile':{'mode':'0','value':['.txt','.avi'],'max_filelen':'400','virus_detection':'1'},'banner':'guss my banner info'}\n"
)
{
	char *json_str = NULL;
	struct ftp_rule_group *group = NULL;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	pthread_rwlock_wrlock(&ftp_lock);
	group = get_protocol_rule(argv[0], SVR_ID_FTP);
	if (!group)
	{
		SCLogInfo("creat group %s\n", argv[0]);
		group = ftp_group_new(argv[0]);
		if (!group)
		{
			pthread_rwlock_unlock(&ftp_lock);
			vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	json_str = argv_concat(argv, argc, 1);
	SCLogInfo("json_str: %s\n", json_str);
	if (group->json_rule)
		json_object_put(group->json_rule);
	group->json_rule = json_tokener_parse(json_str);
	XFREE(MTYPE_TMP, json_str);
	if (!group->json_rule)
	{
		ftp_del_rule_group(group);
		pthread_rwlock_unlock(&ftp_lock);
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* if rule will work */
	group->rule_work = atoi(json_object_get_string(json_object_object_get(group->json_rule, "rule_work")));

	ftp_parse_json_user(group);
	ftp_parse_json_cmd(group);
	ftp_parse_json_keyword_info(group);
	
	ftp_parse_json_upfile(group);
	ftp_parse_json_downfile(group);
	ftp_parse_json_banner_info(group);	

	if (set_protocol_rule(argv[0], SVR_ID_FTP, group) < 0)
	{
		ftp_del_rule_group(group);
		pthread_rwlock_unlock(&ftp_lock);
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	ftp_add_rule_group(group);

	pthread_rwlock_unlock(&ftp_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ftp_add,
	gap_ctl_ftp_add_o_cmd,
	"outer protocol-ftp add groupname NAME rule .JSON",
	"outer machine\n"
	"ftp command\n"
	"add ftp rule\n"
	"groupname\n"
	"name string\n"
	"rule\n"
	"json string, format: {'rule_work':'1','user':{'mode':'1','value':['xxx','xdli']},'command':{'mode':'0','value':['*']},"
	"'upfile':{'mode':'0','value':['.txt','.avi'],'max_filelen':'400','virus_detection':'1'},"
	"'downfile':{'mode':'0','value':['.txt','.avi'],'max_filelen':'400','virus_detection':'1'},'banner':'guss my banner info'}\n"
);

DEFUN(gap_ctl_ftp_del,
	gap_ctl_ftp_del_cmd,
	"protocol-ftp delete groupname NAME",
	"ftp command\n"
	"add ftp rule\n"
	"groupname\n"
	"name string\n"
)
{
	struct ftp_rule_group *group = NULL;

	/* 配置命令是否远端执行 */
	CONF_CMD_RUN();

	pthread_rwlock_rdlock(&ftp_lock);
	group = get_protocol_rule(argv[0], SVR_ID_FTP);
	if (group)
	{
		ftp_del_rule_group(group);
	}
	pthread_rwlock_unlock(&ftp_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ftp_del,
	gap_ctl_ftp_del_o_cmd,
	"outer protocol-ftp delete groupname NAME",
	"outer machine\n"
	"ftp command\n"
	"add ftp rule\n"
	"groupname\n"
	"name string\n"
);

DEFUN(gap_ctl_ftp_view,
	gap_ctl_ftp_view_cmd,
	"show protocol-ftp {groupname NAME}",
	SHOW_STR
	"ftp protocol\n"
	"groupname\n"
	"name string\n"
)
{
	struct ftp_rule_group *group = NULL;
	const char *groupname = argv[0];

	SHOW_CMD_RUN();

	pthread_rwlock_rdlock(&ftp_lock);
	if (groupname)
	{
		group = get_protocol_rule(groupname, SVR_ID_FTP);
		if (group)
		{
			vty_out(vty, "%s%s", json_object_to_json_string_ext(group->json_rule, 0), VTY_NEWLINE);
		}
	}
	else
	{
		hash_iterate(ftp_group_hash, ftp_show_group_iterate, vty);
	}
	pthread_rwlock_unlock(&ftp_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_ftp_view,
	gap_ctl_ftp_view_o_cmd,
	"show outer protocol-ftp {groupname NAME}",
	SHOW_STR
	"ftp protocol\n"
	"groupname\n"
	"name string\n"
);

void ftp_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_ftp_add_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ftp_add_o_cmd);

	install_element(CONFIG_NODE, &gap_ctl_ftp_del_cmd);
	install_element(CONFIG_NODE, &gap_ctl_ftp_del_o_cmd);
}

void ftp_show_cmd_init(unsigned int machine)
{
	if (machine == inner_machine || machine == outer_machine)
	{
		install_element(VIEW_NODE, &gap_ctl_ftp_view_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_ftp_view_o_cmd);

		install_element(VIEW_NODE, &gap_ctl_ftp_view_cmd);
		install_element(ENABLE_NODE, &gap_ctl_ftp_view_cmd);
	}
}

void ftp_cmd_init(void)
{
	pthread_rwlock_init(&ftp_lock, NULL);
	ftp_group_hash = hash_create(ftp_hash_key, ftp_group_hash_cmp);
	register_delete_proto_rule_callback(SVR_ID_FTP, ftp_del_rule_group_extern);
}

void ftp_cmd_exit(void)
{
}

