#ifndef _USER_MGMT_H_
#define _USER_MGMT_H_

#include <pwd.h>
#include <shadow.h>
#include <grp.h>

#define GAP_LOGIN_ACCESS_CONSOLE 1
#define GAP_LOGIN_ACCESS_SSH     2
#define GAP_LOGIN_ACCESS_WEB     4

struct gap_mgmt_group{
    char *group_name;
    int access;
    char *desc;
    char *creator;
    time_t createtime;
    time_t modifytime;
};

#endif