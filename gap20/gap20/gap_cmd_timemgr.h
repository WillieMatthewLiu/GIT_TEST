#ifndef _GAP_CMD_TIMEMGR_H
#define _GAP_CMD_TIMEMGR_H
#include "util-list.h"
#include "gap_cmd.h"

#define TIME_LEN 24
#define TMLIST_NUM 64
#define TMLIST_LEN NAME_LEN*TMLIST_NUM
#define TIME_RANGE 1
#define TIME_GROUP 2
#define TIME_GROUP_SUFFIX "(g)"

enum time_type
{
	Sunday = 0,
	Monday = 1,
	Tuesday = 2,
	Wednesday = 3,
	Thursday = 4,
	Friday = 5,
	Saturday = 6,
	Everyday = 7,
	Oncetime = 8
};

struct timerange
{
	struct list_head n_list; //用于链接到链表上
	char name[NAME_LEN + 1];//名称
	char stime[TIME_LEN];//字段串开始时间
	struct tm stm;//处理后的开始时间，供规则匹配时使用
	char etime[TIME_LEN]; //字段串结束时间
	struct tm etm; //处理后的结束时间，供规则匹配时使用
	int day;//（0-6）表示星期天到星期六，7表示每天，8表示一次性时间
	int refcnt;//引用计数器，为0时才可以被删除
};

struct timegroup
{
	struct list_head n_list; //用于链接到链表上
	char name[NAME_LEN + 1];//名称
	char timelist[TMLIST_LEN]; //时间段列表
	struct timerange *tlist[TMLIST_NUM]; //指向时间段
	int refcnt;//引用计数器，为0时才可以被删除
};

struct time_acl
{
	int type; //两种类型，1表示时间段，2表示时间组
	union
	{
		struct timerange *tr;
		struct timegroup *tg;
	} u;
};

#endif 
