
#include "app_common.h"

#include <zebra.h>

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
#include "memory.h"
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
#include "gap_cmd_timemgr.h"


struct list_head timerange_head = LIST_HEAD_INIT(timerange_head);
struct list_head timegroup_head = LIST_HEAD_INIT(timegroup_head);
pthread_rwlock_t timemgr_lock;

static struct timerange* timerange_get(char *name)
{
	struct timerange *tr, *ret = NULL;
	pthread_rwlock_wrlock(&timemgr_lock);
	list_for_each_entry(tr, &timerange_head, n_list) {
		if (0 == strncmp(tr->name, name, sizeof(tr->name))) {
			/* HIT */
			ret = tr;
			tr->refcnt++;
			break;
		}
	}
	pthread_rwlock_unlock(&timemgr_lock);
	return ret;
}

void __timerange_put(struct timerange *tr)
{
	if (tr == NULL) {
		return;
	}
	tr->refcnt--;
}

static void timerange_put(struct timerange *tr)
{
	pthread_rwlock_wrlock(&timemgr_lock);
	__timerange_put(tr);
	pthread_rwlock_unlock(&timemgr_lock);
}

static struct timegroup* timegroup_get(char *name)
{
	struct timegroup *tg, *ret = NULL;
	pthread_rwlock_wrlock(&timemgr_lock);
	list_for_each_entry(tg, &timegroup_head, n_list) {
		if (0 == strncmp(tg->name, name, sizeof(tg->name))) {
			/* HIT */
			ret = tg;
			tg->refcnt++;
			break;
		}
	}
	pthread_rwlock_unlock(&timemgr_lock);
	return ret;
}

static void timegroup_put(struct timegroup *tg)
{
	if (tg == NULL) {
		return;
	}
	pthread_rwlock_wrlock(&timemgr_lock);
	tg->refcnt--;
	pthread_rwlock_unlock(&timemgr_lock);
}

int set_tm(char *time, struct tm *t)
{
	char *fmt = NULL;
	if (19 == strlen(time)) {
		fmt = "%Y-%m-%d %H:%M:%S";
	}
	else if (16 == strlen(time)) {
		fmt = "%Y-%m-%d %H:%M";
	}
	else if (8 == strlen(time)) {
		fmt = "%H:%M:%S";
	}
	else if (5 == strlen(time)) {
		fmt = "%H:%M";
	}
	else {
		return -1;
	}

	if (strptime(time, fmt, t) != NULL) {
		printf("ok\n");
		printf("%d,%d,%d,%d,%d,%d\n", t->tm_year,
			t->tm_mon,
			t->tm_mday,
			t->tm_hour,
			t->tm_min,
			t->tm_sec);
		return 0;
	}
	return -1;
}

int set_timelist(struct timegroup *tg)
{
	char *p, *out_ptr = NULL;
	int num = 0, i;
	int ret = 0;
	char timelist[TMLIST_LEN], *tlist = timelist;
	strncpy(timelist, tg->timelist, sizeof(timelist) - 1);
	while ((p = strtok_r(tlist, ";,", &out_ptr)) != NULL) {
		if (num >= TMLIST_NUM) {
			SCLogInfo("timelist num overload.");
			return -1;
		}

		tlist = NULL;
		tg->tlist[num] = timerange_get(p);
		if (tg->tlist[num] == NULL) {
			ret = -1;
			break;
		}
		num++;
	}

	if (ret) {
		for (i = 0; i < num; i++) {
			timerange_put(tg->tlist[i]);
		}
	}
	return ret;
}

DEFUN(gap_ctl_timerange,
	gap_ctl_timerange_cmd,
	"timerange (add|edit) name WORD stime WORD etime WORD {day <0-7>}",
	"timerange command\n"
	"add\n"
	"edit\n"
	"timerange's name\n"
	"timerange's name, such as: time1\n"
	"start time\n"
	"time,eg: YYYY-MM-DD/hh:mm[:ss] or hh:mm[:ss]\n"
	"end time\n"
	"time,eg: YYYY-MM-DD/hh:mm[:ss] or hh:mm[:ss]\n"
	"day, day of week\n"
	"0-6: Sunday to Saturday, 7: everyday\n")
{
	struct timerange *tr, *range, *ret = NULL;
	/* ÅäÖÃÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
	CONF_CMD_RUN();

	range = SCMalloc(sizeof(struct timerange));
	if (NULL == range) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	memset(range, 0, sizeof(struct timerange));
	strncpy(range->name, argv[1], sizeof(range->name) - 1);
	strncpy(range->stime, argv[2], sizeof(range->stime) - 1);
	strncpy(range->etime, argv[3], sizeof(range->etime) - 1);
	if (argv[4] == NULL) {
		range->day = Oncetime;
	}
	else {
		range->day = atoi(argv[4]);
	}

	char *p = strchr(argv[2], '/');
	if (p)
		*p = ' ';
	p = strchr(argv[3], '/');
	if (p)
		*p = ' ';
	if (set_tm(argv[2], &range->stm)) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		SCFree(range);
		return CMD_ERR_NOTHING_TODO;
	}
	if (set_tm(argv[3], &range->etm)) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		SCFree(range);
		return CMD_ERR_NOTHING_TODO;
	}

	pthread_rwlock_wrlock(&timemgr_lock);
	list_for_each_entry(tr, &timerange_head, n_list) {
		if (0 == strncmp(tr->name, argv[1], sizeof(tr->name))) {
			/* HIT */
			ret = tr;
			break;
		}
	}

	if (NULL == ret) {
		list_add(&range->n_list, &timerange_head);
	}
	else {
		if (0 == strcmp(argv[0], "add")) {
			vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
			pthread_rwlock_unlock(&timemgr_lock);
			SCFree(range);
			return CMD_ERR_NOTHING_TODO;
		}
		range->n_list = ret->n_list;
		range->refcnt = ret->refcnt;
		memcpy(ret, range, sizeof(*range));
		SCFree(range);
	}
	pthread_rwlock_unlock(&timemgr_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_timerange,
	gap_ctl_timerange_o_cmd,
	"outer timerange (add|edit) name WORD stime WORD etime WORD {day <0-7>}",
	"outer machine\n"
	"timerange command\n"
	"add\n"
	"edit\n"
	"timerange's name\n"
	"timerange's name, such as: time1\n"
	"start time\n"
	"time,eg: YYYY-MM-DD/hh:mm[:ss] or hh:mm[:ss]\n"
	"end time\n"
	"time,eg: YYYY-MM-DD/hh:mm[:ss] or hh:mm[:ss]\n"
	"day, day of week\n"
	"0-6: Sunday to Saturday, 7: everyday\n");

DEFUN(gap_ctl_no_timerange,
	gap_ctl_no_timerange_cmd,
	"no timerange name WORD",
	"no command\n"
	"delete timerange\n"
	"timerange's name\n"
	"timerange's name, such as: time1,time2\n")
{
	struct timerange *tr = NULL;
	int found = 0;
	int ref = 1;
	/* ÅäÖÃÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
	CONF_CMD_RUN();

	char *p, *out_ptr = NULL;
	char timelist[NAME_LEN*DEFAULT_PGSIZE_INT], *tlist = timelist;
	strncpy(timelist, argv[0], sizeof(timelist) - 1);
	while ((p = strtok_r(tlist, ";,", &out_ptr)) != NULL) {
		tlist = NULL;

		pthread_rwlock_wrlock(&timemgr_lock);
		list_for_each_entry(tr, &timerange_head, n_list) {
			if (0 == strncmp(tr->name, p, sizeof(tr->name))) {
				/* HIT */
				if (tr->refcnt == 0) {
					list_del(&tr->n_list);
					SCFree(tr);
					ref = 0;
				}
				found = 1;
				break;
			}
		}
		pthread_rwlock_unlock(&timemgr_lock);

		/* object is used by other*/
		if (ref) {
			vty_result(ERR_CODE_REFERENCDERR, ERR_CODE_REFERENCDERR_DESC);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_no_timerange,
	gap_ctl_no_timerange_o_cmd,
	"outer no timerange name WORD",
	"outer machine\n"
	"no command\n"
	"delete timerange\n"
	"timerange's name\n"
	"timerange's name, such as: time1,time2\n");

DEFUN(gap_ctl_show_timerange,
	gap_ctl_show_timerange_cmd,
	"show timerange {pgindex <1-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"show timerange\n"
	"pageindex\n"
	"1-2147483647\n"
	"pagesize\n"
	"1-2147483647\n")
{
	struct timerange *tr;

	SHOW_CMD_RUN();

	int count = 0;
	char *pageindex = argv[0];
	char *pagesize = argv[1];
	if (pageindex == NULL) {
		pageindex = DEFAULT_PGINDEX;
	}
	if (pagesize == NULL) {
		pagesize = DEFAULT_PGSIZE;
	}
	int pgindex = atoi(pageindex);
	int pgsize = atoi(pagesize);

	pthread_rwlock_rdlock(&timemgr_lock);
	list_for_each_entry(tr, &timerange_head, n_list) {
		if ((pgindex == 0) || (count >= ((pgindex - 1)*pgsize) && count < (pgindex*pgsize))) {
			vty_out(vty, "%s  %s  %s  %d%s", tr->name, tr->stime, tr->etime, tr->day, VTY_NEWLINE);
		}
		count++;
	}
	pthread_rwlock_unlock(&timemgr_lock);

	vty_out(vty, "[pageindex=%d,pagesize=%d,totalline=%d]%s", pgindex, pgsize, count, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_show_timerange,
	gap_ctl_show_timerange_o_cmd,
	"show outer timerange {pgindex <1-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"outer machine\n"
	"show timerange\n"
	"pageindex\n"
	"1-2147483647\n"
	"pagesize\n"
	"1-2147483647\n");

DEFUN(gap_ctl_show_timerange_by_name,
	gap_ctl_show_timerange_by_name_cmd,
	"show timerange name WORD",
	SHOW_STR
	"show timerange\n"
	"timerange's name\n"
	"timerange's name, such as:time1\n")
{
	struct timerange *tr;

	SHOW_CMD_RUN();

	pthread_rwlock_rdlock(&timemgr_lock);
	list_for_each_entry(tr, &timerange_head, n_list) {
		if (0 == strncmp(tr->name, argv[0], sizeof(tr->name))) {
			vty_out(vty, "%s  %s  %s  %d%s", tr->name, tr->stime, tr->etime, tr->day, VTY_NEWLINE);
		}
	}
	pthread_rwlock_unlock(&timemgr_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_show_timerange_by_name,
	gap_ctl_show_timerange_by_name_o_cmd,
	"show outer timerange name WORD",
	SHOW_STR
	"show timerange\n"
	"outer machine\n"
	"timerange's name\n"
	"timerange's name, such as:time1\n");

DEFUN(gap_ctl_timegroup,
	gap_ctl_timegroup_cmd,
	"timegroup (add|edit) name WORD timerangelist WORD",
	"timegroup command\n"
	"add\n"
	"edit\n"
	"timegroup's name\n"
	"timegroup's name, such as: timeg1\n"
	"timerange list\n"
	"timerange list: such as: time1,time2,time3\n")
{
	struct timegroup *tg, *group, *ret = NULL;
	/* ÅäÖÃÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
	CONF_CMD_RUN();

	group = SCMalloc(sizeof(struct timegroup));
	if (NULL == group) {
		vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}
	memset(group, 0, sizeof(struct timegroup));
	strncpy(group->name, argv[1], sizeof(group->name) - 1);
	strncpy(group->timelist, argv[2], sizeof(group->timelist) - 1);
	if (set_timelist(group)) {
		SCFree(group);
		vty_result(ERR_CODE_DEPENDENTERR, ERR_CODE_DEPENDENTERR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	pthread_rwlock_wrlock(&timemgr_lock);
	list_for_each_entry(tg, &timegroup_head, n_list) {
		if (0 == strncmp(tg->name, argv[1], sizeof(tg->name))) {
			/* HIT */
			ret = tg;
			break;
		}
	}

	if (NULL == ret) {
		list_add(&group->n_list, &timegroup_head);
	}
	else {
		if (0 == strcmp(argv[0], "add")) {
			vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
			pthread_rwlock_unlock(&timemgr_lock);
			SCFree(group);
			return CMD_ERR_NOTHING_TODO;
		}
		int i;
		for (i = 0; i < TMLIST_NUM; i++) {
			__timerange_put(ret->tlist[i]);/* ÊÍ·Å¾ÉµÄÒýÓÃ¼ÆÊý */
		}
		group->n_list = ret->n_list;
		group->refcnt = ret->refcnt;
		memcpy(ret, group, sizeof(*group));
		SCFree(group);
	}
	pthread_rwlock_unlock(&timemgr_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_timegroup,
	gap_ctl_timegroup_o_cmd,
	"outer timegroup (add|edit) name WORD timerangelist WORD",
	"outer machine\n"
	"timegroup command\n"
	"add\n"
	"edit\n"
	"timegroup's name\n"
	"timegroup's name, such as: timeg1\n"
	"timerange list\n"
	"timerange list: such as: time1,time2,time3\n");

DEFUN(gap_ctl_no_timegroup,
	gap_ctl_no_timegroup_cmd,
	"no timegroup name WORD",
	"no command\n"
	"delete timegroup\n"
	"timegroup's name\n"
	"timegroup's name, such as: timeg1,timeg2\n")
{
	struct timegroup *tg = NULL;
	int found = 0;
	int ref = 1;
	/* ÅäÖÃÃüÁîÊÇ·ñÔ¶¶ËÖ´ÐÐ */
	CONF_CMD_RUN();

	char *p, *out_ptr = NULL;
	char timelist[NAME_LEN*DEFAULT_PGSIZE_INT], *tlist = timelist;
	strncpy(timelist, argv[0], sizeof(timelist) - 1);
	while ((p = strtok_r(tlist, ";,", &out_ptr)) != NULL) {
		tlist = NULL;
		pthread_rwlock_wrlock(&timemgr_lock);
		list_for_each_entry(tg, &timegroup_head, n_list) {
			if (0 == strncmp(tg->name, p, sizeof(tg->name))) {
				/* HIT */
				if (tg->refcnt == 0) {
					int i;
					for (i = 0; i < TMLIST_NUM; i++) {
						__timerange_put(tg->tlist[i]);/* ÊÍ·ÅÒýÓÃ¼ÆÊý */
					}
					list_del(&tg->n_list);
					SCFree(tg);
					ref = 0;
				}
				found = 1;
				break;
			}
		}
		pthread_rwlock_unlock(&timemgr_lock);

		/* object is used by other*/
		if (ref) {
			vty_result(ERR_CODE_REFERENCDERR, ERR_CODE_REFERENCDERR_DESC);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_no_timegroup,
	gap_ctl_no_timegroup_o_cmd,
	"outer no timegroup name WORD",
	"outer machine\n"
	"no command\n"
	"delete timegroup\n"
	"timegroup's name\n"
	"timegroup's name, such as: timeg1,timeg2\n");

DEFUN(gap_ctl_show_timegroup,
	gap_ctl_show_timegroup_cmd,
	"show timegroup {pgindex <1-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"show timegroup\n"
	"pageindex\n"
	"1-2147483647\n"
	"pagesize\n"
	"1-2147483647\n")
{
	struct timegroup *tg;

	SHOW_CMD_RUN();

	int count = 0;
	char *pageindex = argv[0];
	char *pagesize = argv[1];
	if (pageindex == NULL) {
		pageindex = DEFAULT_PGINDEX;
	}
	if (pagesize == NULL) {
		pagesize = DEFAULT_PGSIZE;
	}
	int pgindex = atoi(pageindex);
	int pgsize = atoi(pagesize);

	pthread_rwlock_rdlock(&timemgr_lock);
	list_for_each_entry(tg, &timegroup_head, n_list) {
		if ((pgindex == 0) || (count >= ((pgindex - 1)*pgsize) && count < (pgindex*pgsize))) {
			vty_out(vty, "%s  %s%s", tg->name, tg->timelist, VTY_NEWLINE);
		}
		count++;
	}
	pthread_rwlock_unlock(&timemgr_lock);

	vty_out(vty, "[pageindex=%d,pagesize=%d,totalline=%d]%s", pgindex, pgsize, count, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_show_timegroup,
	gap_ctl_show_timegroup_o_cmd,
	"show outer timegroup {pgindex <1-2147483647>|pgsize <1-2147483647>}",
	SHOW_STR
	"outer machine\n"
	"show timegroup\n"
	"pageindex\n"
	"1-2147483647\n"
	"pagesize\n"
	"1-2147483647\n");

DEFUN(gap_ctl_show_timegroup_by_name,
	gap_ctl_show_timegroup_by_name_cmd,
	"show timegroup name WORD",
	SHOW_STR
	"show timegroup\n"
	"timegroup's name\n"
	"timegroup's name, such as:timeg1\n")
{
	struct timegroup *tg;

	SHOW_CMD_RUN();

	pthread_rwlock_rdlock(&timemgr_lock);
	list_for_each_entry(tg, &timegroup_head, n_list) {
		if (0 == strncmp(tg->name, argv[0], sizeof(tg->name))) {
			vty_out(vty, "%s  %s%s", tg->name, tg->timelist, VTY_NEWLINE);
		}
	}
	pthread_rwlock_unlock(&timemgr_lock);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_show_timegroup_by_name,
	gap_ctl_show_timegroup_by_name_o_cmd,
	"show outer timegroup name WORD",
	SHOW_STR
	"show timegroup\n"
	"outer machine\n"
	"timegroup's name\n"
	"timegroup's name, such as:timeg1\n");

DEFUN(gap_ctl_show_timelist,
	gap_ctl_show_timelist_cmd,
	"show timelist",
	SHOW_STR
	"show timelist, Contains timerange and timegroup\n")
{
	struct timerange *tr;
	struct timegroup *tg;

	SHOW_CMD_RUN();
	pthread_rwlock_rdlock(&timemgr_lock);
	list_for_each_entry(tr, &timerange_head, n_list) {
		vty_out(vty, "%s,", tr->name);
	}
	list_for_each_entry(tg, &timegroup_head, n_list) {
		vty_out(vty, "%s%s,", tg->name, TIME_GROUP_SUFFIX);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	pthread_rwlock_unlock(&timemgr_lock);

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_show_timelist,
	gap_ctl_show_timelist_o_cmd,
	"show outer timelist",
	SHOW_STR
	"outer machine"
	"show timelist, Contains timerange and timegroup\n");

void timemgr_get(struct time_acl *acl, char *name)
{
	memset(acl, 0, sizeof(*acl));
	if (strlen(name) == 0)
		return;

	char ch;
	char *token = strstr(name, TIME_GROUP_SUFFIX);
	if (token) {
		ch = *token;
		*token = '\0';
		acl->type = TIME_GROUP;
		acl->u.tg = timegroup_get(name);
		*token = ch;
	}
	else {
		acl->type = TIME_RANGE;
		acl->u.tr = timerange_get(name);
	}

}

void timemgr_put(struct time_acl *acl)
{
	if (acl->type == TIME_RANGE) {
		timerange_put(acl->u.tr);
	}
	else if (acl->type == TIME_GROUP) {
		timegroup_put(acl->u.tg);
	}
	else {
		SCLogInfo("time_acl is null.");
	}
}

static int in_timerange(struct tm now_tm, struct timerange *tr)
{
	if (tr->day == Oncetime) {
		time_t start = mktime(&tr->stm);
		time_t end = mktime(&tr->etm);
		time_t now = mktime(&now_tm);
		if (now >= start && now <= end) {
			return 1;
		}
		return 0;
	}
	else if (tr->day == Everyday) {
		goto common;
	}
	else {
		if (now_tm.tm_wday == tr->day) {
			goto common;
		}
		return 0;
	}

common:
	;
	time_t s = tr->stm.tm_hour * 3600 + tr->stm.tm_min * 60 + tr->stm.tm_sec;
	time_t e = tr->etm.tm_hour * 3600 + tr->etm.tm_min * 60 + tr->etm.tm_sec;
	time_t n = now_tm.tm_hour * 3600 + now_tm.tm_min * 60 + now_tm.tm_sec;
	if (n >= s && n <= e) {
		return 1;
	}

	return 0;
}

/*·µ»ØÖµ:0·ÅÐÐ  -1×è¶Ï*/
int check_time_privilege(struct time_acl *tacl)
{
	if (tacl->u.tr == NULL)
		return 0;

	time_t now = time(NULL);
	struct tm now_tm;
	localtime_r(&now, &now_tm);
	if (tacl->type == TIME_RANGE) {
		if (tacl->u.tr && in_timerange(now_tm, tacl->u.tr)) {
			return 0;
		}
	}
	else if (tacl->type == TIME_GROUP) {
		if (tacl->u.tg) {
			int i;
			for (i = 0; i < TMLIST_NUM; i++) {
				if (tacl->u.tg->tlist[i] && in_timerange(now_tm, tacl->u.tg->tlist[i])) {
					return 0;
				}
			}
		}
	}
	else {
		return 0;
	}

	return -1;
}

int timemgr_config_write(struct vty *vty)
{
	struct timerange *tr;
	struct timegroup *tg;

	pthread_rwlock_rdlock(&timemgr_lock);
	list_for_each_entry(tr, &timerange_head, n_list) {
		if (tr->day == Oncetime) {
			vty_out(vty, "timerange add name %s stime %s etime %s%s", tr->name, tr->stime, tr->etime, VTY_NEWLINE);
		}
		else {
			vty_out(vty, "timerange add name %s stime %s etime %s day %d%s", tr->name, tr->stime, tr->etime, tr->day, VTY_NEWLINE);
		}
	}

	list_for_each_entry(tg, &timegroup_head, n_list) {
		vty_out(vty, "timegroup add name %s timerangelist %s%s", tg->name, tg->timelist, VTY_NEWLINE);
	}
	pthread_rwlock_unlock(&timemgr_lock);

	return 0;
}

void timemgr_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_timerange_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_no_timerange_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_timegroup_o_cmd);
	install_element(CONFIG_NODE, &gap_ctl_no_timegroup_o_cmd);

	install_element(CONFIG_NODE, &gap_ctl_timerange_cmd);
	install_element(CONFIG_NODE, &gap_ctl_no_timerange_cmd);
	install_element(CONFIG_NODE, &gap_ctl_timegroup_cmd);
	install_element(CONFIG_NODE, &gap_ctl_no_timegroup_cmd);
}

void timemgr_show_cmd_init(unsigned int machine)
{
	if (machine == outer_machine || machine == inner_machine) {
		install_element(VIEW_NODE, &gap_ctl_show_timerange_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_show_timerange_o_cmd);
		install_element(VIEW_NODE, &gap_ctl_show_timegroup_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_show_timegroup_o_cmd);
		install_element(VIEW_NODE, &gap_ctl_show_timelist_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_show_timelist_o_cmd);
		install_element(VIEW_NODE, &gap_ctl_show_timerange_by_name_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_show_timerange_by_name_o_cmd);
		install_element(VIEW_NODE, &gap_ctl_show_timegroup_by_name_o_cmd);
		install_element(ENABLE_NODE, &gap_ctl_show_timegroup_by_name_o_cmd);
	}

	install_element(VIEW_NODE, &gap_ctl_show_timerange_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_timerange_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_timegroup_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_timegroup_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_timelist_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_timelist_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_timerange_by_name_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_timerange_by_name_cmd);
	install_element(VIEW_NODE, &gap_ctl_show_timegroup_by_name_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_timegroup_by_name_cmd);
}

void timemgr_init(void)
{
	pthread_rwlock_init(&timemgr_lock, NULL);
}

void timemgr_exit(void)
{
	do {
		struct timegroup *tg, *next;
		pthread_rwlock_wrlock(&timemgr_lock);
		list_for_each_entry_safe(tg, next, &timegroup_head, n_list) {
			list_del(&tg->n_list);
			SCFree(tg);
		}
		pthread_rwlock_unlock(&timemgr_lock);
	} while (0);

	do {
		struct timerange *tr, *next;
		pthread_rwlock_wrlock(&timemgr_lock);
		list_for_each_entry_safe(tr, next, &timerange_head, n_list) {
			list_del(&tr->n_list);
			SCFree(tr);
		}
		pthread_rwlock_unlock(&timemgr_lock);
	} while (0);
}

