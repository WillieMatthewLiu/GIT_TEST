#ifndef _GAP_CMD_ACCOUNT_H_
#define _GAP_CMD_ACCOUNT_H_

#define SSH_LOGIN_PERMISSION_DISABLE "-:ALL:ALL except LOCAL\n"
#define CONSOLE_LOGIN_PERMISSION_DISABLE "-:ALL:LOCAL\n"

#define ACCESS_RULE_HEAD_SSH "-:ALL EXCEPT root admin "
#define ACCESS_RULE_TAIL_SSH ":ALL EXCEPT LOCAL\n"
#define ACCESS_RULE_HEAD_CONSOLE "-:ALL EXCEPT root admin "
#define ACCESS_RULE_TAIL_CONSOLE ":LOCAL\n"
#define ACCESS_CONF_FILE_PATH "/etc/security/access.conf"

#define SYS_USER_ACTIVE_TIME (20) //minute
#define SYS_USER_MAX_LOGIN_ERRTIMES (5) 

enum access_flag {
	ACCESS_FLAG_WEB = 0,
	ACCESS_FLAG_SSH,
	ACCESS_FLAG_CONSOLE,
};

enum privilege_manage_flag {
	PRIVILEGE_FLAG_USER_MANAGEMENT = 0,
	PRIVILEGE_FLAG_DEV_MAINTAINS,
	PRIVILEGE_FLAG_NETWORK_MANAGEMENT,
	PRIVILEGE_FLAG_HA_PAYLOAD_BALANCE,
	PRIVILEGE_FLAG_CONF_IMPORT_EXPORT,
	PRIVILEGE_FLAG_SECURE_CONF_MODIFY,
	PRIVILEGE_FLAG_AUDIT_MANAGEMENT,
	PRIVILEGE_FLAG_TRAFFIC_STATISTICS,
};

struct sys_user_group {
	struct list_head n_list;
	char groupname[NAME_LEN + 1];
	uint64_t privilege_flags;
	uint64_t access_flags; // web,ssh2,console,...
	char *creator;
	int64_t createtime;
	char *comment;
	struct list_head users; /* user list belong this group */
};

struct sys_user {
	struct list_head n_list;
	struct sys_user_group *group;
	char username[NAME_LEN + 1];
	int user_enable;// 1:enable, 0:disable
	char creator[NAME_LEN + 1];
	int64_t createtime;
	int64_t lastlogintime;
	char *comment;
};

#endif
