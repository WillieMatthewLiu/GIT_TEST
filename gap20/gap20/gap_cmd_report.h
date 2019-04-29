#ifndef _GAP_CMD_REPORT_H
#define _GAP_CMD_REPORT_H
#include "gap_cmd.h"

#define TIMELY_ENABLE 1
#define TIMELY_DISABLE 0

enum e_periodic
{
	periodic_none,
	periodic_daily,
	periodic_weekly,
	periodic_monthly
};

struct email_periodic_report
{
	int periodic; /*0:不报告、1:每日报告、2:每周报告、3:每月报告 (单选)*/
	char *logs; /*"op":操作日志、"sys":系统日志、"eventaudit":事件审计日志、"accessaudit":访问审计日志、"sesson"：会话统计日志 (多选，用逗号分隔)*/
	char *smtp_server; /* smtp服务器 */
	char *smtp_user; /* smtp用户 */
	char *smtp_passwd; /* smtp密码 */
	char *dest_email; /* 目的邮箱 */

	char *json;//前台配置的参数字符串
	struct json_object *jobj;//前台配置的参数转化成json格式
	struct thread *thread;/* 定时器句柄 */
	int interval;/* 定时间隔 */
};

struct email_timely_alarm
{
	int enable; /* 1：启用  0：禁用 */
	char *module; /* "sys":系统事件，"access":访问事件 (多选，用逗号分隔)*/
	int level;/* 0:critical, 1:error,2:warn, 3:info */
	int frequency; /*5~3600秒*/
	char *smtp_server; /* smtp服务器 */
	char *smtp_user; /* smtp用户 */
	char *smtp_passwd; /* smtp密码 */
	char *dest_email; /* 目的邮箱 */

	char *json;//前台配置的参数字符串
	struct json_object *jobj;//前台配置的参数转化成json格式
	struct thread *thread;/* 定时器句柄 */
	int interval;/* 定时间隔 */
};

int report_config_write(struct vty *vty);
void report_conf_cmd_init(void);
void report_show_cmd_init(unsigned int machine);
void report_init(void);
void report_exit(void);

#endif 
