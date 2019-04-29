#ifndef _GAP_CTL_H
#define _GAP_CTL_H
#include "command.h"
#include "util-list.h"
#include "util-mem.h"
#include "oscall.h"
#include "gap_ctl_conf.h"
#include "gap_cmd.h"
#include "gap_cmd_route.h"

#define DEV_NULL " 2> /dev/null"
#define GAP_VTY_PORT 2601
#define TEMPLATE_IP "0.0.0.0"

#define ERR_CODE_SUCCESS  1
#define ERR_CODE_EXIST    2
#define ERR_CODE_DATABASEERROR 3
#define ERR_CODE_CONF_LOCKED 4
#define ERR_CODE_NOTFOUND 5
#define ERR_CODE_SYSERROR 6
#define ERR_CODE_PARAMERROR 7
#define ERR_CODE_NOTSUPPORT 8
#define ERR_CODE_CONFLICT 9
#define ERR_CODE_RELOADERR 10
#define ERR_CODE_CALLBACKERR 11
#define ERR_CODE_DEPENDENTERR 12
#define ERR_CODE_REFERENCDERR 13
#define ERR_CODE_TIMEOUT 14
#define ERR_CODE_PERMISSION_DENIED 15
#define ERR_CODE_NOMATCH 16
#define ERR_CODE_NAMEERR 17
#define ERR_CODE_JSONERR 18

#define ERR_CODE_SUCCESS_DESC   "Success"
#define ERR_CODE_EXIST_DESC     "Object exsit"
#define ERR_CODE_NOTFOUND_DESC  "Not found"
#define ERR_CODE_SYSERROR_DESC   "System error"
#define ERR_CODE_PARAMERROR_DESC "Parameter error"
#define ERR_CODE_DATABASEERROR_DESC "Database error"
#define ERR_CODE_NOTSUPPORT_DESC "Not support"
#define ERR_CODE_CONFLICT_DESC "Data conflict"
#define ERR_CODE_RELOADERR_DESC "Reload config err"
#define ERR_CODE_CALLBACKERR_DESC "Callback function err"
#define ERR_CODE_DEPENDENTERR_DESC "Dependent object does not exist"
#define ERR_CODE_REFERENCDERR_DESC "Referenced objects exist"
#define ERR_CODE_TIMEOUT_DESC "Timeout"
#define ERR_CODE_PERMISSION_DENIED_DESC "permission denied"
#define ERR_CODE_CONF_LOCKED_DESC "Arbiter config locked"
#define ERR_CODE_NOMATCH_DESC "Config no match"
#define ERR_CODE_NAMEERR_DESC "name error"
#define ERR_CODE_JSONERR_DESC "json format error"


#define SQLITE3_PARAM ""//"pragma synchronous=\'off\';pragma journal_model=\'memory\';"

#define vty_result(code, description) vty_out(vty, "%d|%s%s", code,description, VTY_NEWLINE)

enum mach {
	inner_machine = 0,//BOARDTYPE_IN,
	outer_machine = 1, //BOARDTYPE_OUT,
	arbiter_machine = 2, //BOARDTYPE_ARBITER
};

static inline void urldecode(char *p)
{
	int i = 0;
	while (*(p + i)) {
		if ((*p = *(p + i)) == '%') {
			*p = *(p + i + 1) >= 'A' ? ((*(p + i + 1) & 0XDF) - 'A') + 10 : (*(p + i + 1) - '0');
			*p = (*p) * 16;
			*p += *(p + i + 2) >= 'A' ? ((*(p + i + 2) & 0XDF) - 'A') + 10 : (*(p + i + 2) - '0');
			i += 2;
		}
		else if (*(p + i) == '+') {
			*p = ' ';
		}
		p++;
	}
	*p = '\0';
}

static inline void get_sys_time(char *value, int len, char *format)
{
	time_t t = time(0);
	char buf[64];
	strftime(buf, sizeof(buf), format, localtime(&t));
	strncpy(value, buf, len);
}

typedef int(*interface_fun)(struct gap_interface *old, struct gap_interface *new);
typedef int(*route_fun)(struct gap_route *old, struct gap_route *new);
typedef char* (*print_session_fun)(char *proto, char *user, char *sip, char *dip, int pageindex, int pagesize);

#define WARM_SYNC(cmd) 

unsigned int get_cur_machine(void);
int gap_vty_init(unsigned int machine);
void gap_vty_exit(void);
int gap_ctl_init(unsigned int machine);
void gap_ctl_exit(void);

#endif 
