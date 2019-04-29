#include "app_common.h"

#include <zebra.h>
#include <json-c/json.h>

#define _XOPEN_SOURCE
#include <unistd.h>

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
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#ifdef USE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#endif

#include <readline/readline.h>
#include <readline/history.h>
#include <termios.h>
#include "command.h"
#include "lib/memory.h"
#include "buffer.h"
#include "vtysh/vtysh.h"
#include "bitops.h"
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
#include "filter.h"

#include "gap_ctl.h"
#include "gap_ctl_adapter.h"
#include "main_inouter.h"
#include "gapconfig.h"
#include "gap_cmd_account.h"
#include "json-c.h"

#define GAP_SYS_GROUP_FILE "/etc/gap_sys_user.conf"

static struct list_head sys_group_head;
static int active_time = SYS_USER_ACTIVE_TIME;
static int max_login_errtimes = SYS_USER_MAX_LOGIN_ERRTIMES;

static const char *access_str[] = {
	[ACCESS_FLAG_WEB] = "web",
	[ACCESS_FLAG_SSH] = "ssh",
	[ACCESS_FLAG_CONSOLE] = "console",
};

static const char *privilege_str[] = {
	[PRIVILEGE_FLAG_USER_MANAGEMENT] = "usrmgm",
	[PRIVILEGE_FLAG_DEV_MAINTAINS] = "device",
	[PRIVILEGE_FLAG_NETWORK_MANAGEMENT] = "network",
	[PRIVILEGE_FLAG_HA_PAYLOAD_BALANCE] = "highavailable",
	[PRIVILEGE_FLAG_CONF_IMPORT_EXPORT] = "configure",
	[PRIVILEGE_FLAG_SECURE_CONF_MODIFY] = "rule",
	[PRIVILEGE_FLAG_AUDIT_MANAGEMENT] = "audit",
	[PRIVILEGE_FLAG_TRAFFIC_STATISTICS] = "traffic",
};

static struct sys_user * sys_user_new(void)
{
	struct sys_user *sys_user = NULL;

	sys_user = XMALLOC(MTYPE_TMP, sizeof(*sys_user));
	if (!sys_user)
		return NULL;
	memset(sys_user, 0, sizeof(*sys_user));
	return sys_user;
}

static void sys_user_free(struct sys_user *sys_user)
{
	if (sys_user->comment)
		XFREE(MTYPE_TMP, sys_user->comment);
	XFREE(MTYPE_TMP, sys_user);
}

static struct sys_user_group * sys_user_group_new(void)
{
	struct sys_user_group *sys_group = NULL;

	sys_group = XMALLOC(MTYPE_TMP, sizeof(*sys_group));
	if (!sys_group)
		return NULL;

	memset(sys_group, 0, sizeof(*sys_group));
	INIT_LIST_HEAD(&sys_group->users);
	return sys_group;
}

static void sys_user_group_free(struct sys_user_group *sys_group)
{
	if (sys_group->comment)
		XFREE(MTYPE_TMP, sys_group->comment);
	if (sys_group->creator)
		XFREE(MTYPE_TMP, sys_group->creator);
	XFREE(MTYPE_TMP, sys_group);
}


static struct sys_user_group * find_sys_user_group(const char *groupname)
{
	struct sys_user_group *sys_group = NULL;
	int found = 0;
	list_for_each_entry(sys_group, &sys_group_head, n_list)
	{
		if (0 == strcmp(sys_group->groupname, groupname))
		{
			found = 1;
			break;
		}
	}

	if (!found)
		sys_group = NULL;

	return sys_group;
}

static struct sys_user *find_sys_user(const char *groupname, const char *username)
{
	struct sys_user_group *gpos;
	struct sys_user *sys_user = NULL;

	list_for_each_entry(gpos, &sys_group_head, n_list) {
		if (!groupname
			|| (groupname && (strcmp(groupname, gpos->groupname) == 0)))
		{
			list_for_each_entry(sys_user, &gpos->users, n_list)
			{
				if (0 == strcmp(sys_user->username, username))
				{
					return sys_user;
				}
			}
		}
	}

	return NULL;
}

static void del_sys_user(struct sys_user *sys_user)
{
	list_del(&sys_user->n_list);
	cmd_system_novty_arg("userdel -r %s", sys_user->username);
	sys_user_free(sys_user);
}

static void del_sys_user_group(struct sys_user_group *sys_group)
{
	struct sys_user *user;
	struct sys_user *usern;

	list_del(&sys_group->n_list);
	list_for_each_entry_safe(user, usern, &sys_group->users, n_list)
	{
		del_sys_user(user);
	}
	cmd_system_novty_arg("groupdel %s", sys_group->groupname);
	sys_user_group_free(sys_group);
}

static void flush_access_conf_file()
{
	uint8_t *p;
	int length;
	struct sys_user *sys_user = NULL;
	struct sys_user_group *sys_group = NULL;
	struct evbuffer *cache_buf = evbuffer_new();
	FILE *conf_file = NULL;

	if (!cache_buf)
		return;

	if (g_gapcfg->ssh_login_permission)
	{
		evbuffer_add(cache_buf, ACCESS_RULE_HEAD_SSH, strlen(ACCESS_RULE_HEAD_SSH));
		list_for_each_entry(sys_group, &sys_group_head, n_list)
		{
			if (__test_bit(ACCESS_FLAG_SSH, &sys_group->access_flags))
			{
				list_for_each_entry(sys_user, &sys_group->users, n_list)
				{
					evbuffer_add(cache_buf, sys_user->username, strlen(sys_user->username));
					evbuffer_add(cache_buf, " ", 1);
				}
			}
		}
		evbuffer_add(cache_buf, ACCESS_RULE_TAIL_SSH, strlen(ACCESS_RULE_TAIL_SSH));
	}
	else
		evbuffer_add(cache_buf, SSH_LOGIN_PERMISSION_DISABLE, strlen(SSH_LOGIN_PERMISSION_DISABLE));

	if (g_gapcfg->console_login_permission)
	{
		evbuffer_add(cache_buf, ACCESS_RULE_HEAD_CONSOLE, strlen(ACCESS_RULE_HEAD_CONSOLE));
		list_for_each_entry(sys_group, &sys_group_head, n_list)
		{
			if (__test_bit(ACCESS_FLAG_CONSOLE, &sys_group->access_flags))
			{
				list_for_each_entry(sys_user, &sys_group->users, n_list)
				{
					evbuffer_add(cache_buf, sys_user->username, strlen(sys_user->username));
					evbuffer_add(cache_buf, " ", 1);
				}
			}
		}
		evbuffer_add(cache_buf, ACCESS_RULE_TAIL_CONSOLE, strlen(ACCESS_RULE_TAIL_CONSOLE));
	}
	else
		evbuffer_add(cache_buf, CONSOLE_LOGIN_PERMISSION_DISABLE, strlen(CONSOLE_LOGIN_PERMISSION_DISABLE));

	length = (int)evbuffer_get_length(cache_buf);
	p = evbuffer_pullup(cache_buf, evbuffer_get_length(cache_buf));

	conf_file = fopen(ACCESS_CONF_FILE_PATH, "w+");
	if (!conf_file)
		goto err;
	fwrite(p, length, 1, conf_file);
	fclose(conf_file);

err:
	evbuffer_free(cache_buf);
}

static void access_str2flags(uint64_t *access_flags, const char *access)
{
	switch (access[0]) {
	case 'c':
		__set_bit(ACCESS_FLAG_CONSOLE, access_flags);
		break;
	case 's':
		__set_bit(ACCESS_FLAG_SSH, access_flags);
		break;
	case 'w':
		__set_bit(ACCESS_FLAG_WEB, access_flags);
		break;
	default:
		break;
	}
}

static void privilege_str2flags(uint64_t *privilege_flags, const char *privilege)
{
	switch (privilege[0]) {
	case 'a':
		__set_bit(PRIVILEGE_FLAG_AUDIT_MANAGEMENT, privilege_flags);
		break;
	case 'c':
		__set_bit(PRIVILEGE_FLAG_CONF_IMPORT_EXPORT, privilege_flags);
		break;
	case 'd':
		__set_bit(PRIVILEGE_FLAG_DEV_MAINTAINS, privilege_flags);
		break;
	case 'h':
		__set_bit(PRIVILEGE_FLAG_HA_PAYLOAD_BALANCE, privilege_flags);
		break;
	case 'r':
		__set_bit(PRIVILEGE_FLAG_SECURE_CONF_MODIFY, privilege_flags);
		break;
	case 'n':
		__set_bit(PRIVILEGE_FLAG_NETWORK_MANAGEMENT, privilege_flags);
		break;
	case 't':
		__set_bit(PRIVILEGE_FLAG_TRAFFIC_STATISTICS, privilege_flags);
		break;
	case 'u':
		__set_bit(PRIVILEGE_FLAG_USER_MANAGEMENT, privilege_flags);
		break;
	default:
		break;
	}

}

static void users_json_init(struct sys_user_group *sys_group, struct json_object *jboj)
{
	struct sys_user *sys_user = NULL;
	struct json_object *user_obj = NULL;

	list_for_each_entry(sys_user, &sys_group->users, n_list)
	{
		user_obj = json_object_new_object();

		json_object_object_add(user_obj, "user_enable", json_object_new_int(sys_user->user_enable));
		json_object_object_add(user_obj, "creator", json_object_new_string(sys_user->creator));
		json_object_object_add(user_obj, "createtime", json_object_new_int64(sys_user->createtime));
		json_object_object_add(user_obj, "lastlogintime", json_object_new_int64(sys_user->lastlogintime));
		if (sys_user->comment)
			json_object_object_add(user_obj, "comment", json_object_new_string(sys_user->comment));

		json_object_object_add(jboj, sys_user->username, user_obj);
	}
}

static void load_sys_group_jsonfile()
{
	int i;
	const char *temp;
	struct sys_user_group *sys_group;
	struct sys_user *sys_user;
	struct json_object *jobj = json_object_from_file(GAP_SYS_GROUP_FILE);

	if (!jobj)
		return;

	/* iterator jobj to create group list */
	json_object_object_foreach(jobj, key, val)
	{
		if (!strcmp(key, "active_time"))
		{
			active_time = json_object_get_int(val);
		}
		else if (!strcmp(key, "login_errtimes"))
		{
			max_login_errtimes = json_object_get_int(val);
		}
		else if (!strcmp(key, "groups"))
		{
			json_object_object_foreach(val, groups_key, group)
			{
				SCLogInfo("group: %s\n", groups_key);
				sys_group = sys_user_group_new();
				if (!sys_group)
					continue;
				list_add(&sys_group->n_list, &sys_group_head);
				strncpy(sys_group->groupname, groups_key, sizeof(sys_group->groupname) - 1);

				json_object_object_foreach(group, group_key, group_val)
				{
					SCLogInfo("group_key: %s\n", group_key);
					if (!strcmp(group_key, "privilege"))
					{
						for (i = 0; i < json_object_array_length(group_val); i++) {
							temp = json_object_get_string(json_object_array_get_idx(group_val, i));
							privilege_str2flags(&sys_group->privilege_flags, temp);
						}
					}
					else if (!strcmp(group_key, "access"))
					{
						for (i = 0; i < json_object_array_length(group_val); i++) {
							temp = json_object_get_string(json_object_array_get_idx(group_val, i));
							access_str2flags(&sys_group->access_flags, temp);
						}
					}
					else if (!strcmp(group_key, "creator"))
					{
						sys_group->creator = XSTRDUP(MTYPE_TMP, json_object_get_string(group_val));
					}
					else if (!strcmp(group_key, "createtime"))
					{
						sys_group->createtime = json_object_get_int64(group_val);
					}
					else if (!strcmp(group_key, "comment"))
					{
						sys_group->comment = SCStrdup(json_object_get_string(group_val));
					}
					else if (!strcmp(group_key, "users"))
					{
						json_object_object_foreach(group_val, users_key, user)
						{
							sys_user = sys_user_new();
							if (!sys_user)
								continue;
							sys_user->group = sys_group;
							list_add(&sys_user->n_list, &sys_group->users);
							strncpy(sys_user->username, users_key, sizeof(sys_user->username) - 1);

							json_object_object_foreach(user, user_key, user_val)
							{
								if ((!strcmp(user_key, "user_enable")))
									sys_user->user_enable = json_object_get_int(user_val);
								else if (!strcmp(user_key, "creator"))
									strncpy(sys_user->creator, json_object_get_string(user_val), sizeof(sys_user->creator) - 1);
								else if (!strcmp(user_key, "createtime"))
									sys_user->createtime = json_object_get_int64(user_val);
								else if (!strcmp(user_key, "lastlogintime"))
									sys_user->lastlogintime = json_object_get_int64(user_val);
								else if (!strcmp(user_key, "comment"))
									sys_user->comment = SCStrdup(json_object_get_string(user_val));
							}
						}
					}
				}
			}
		}
	}

	/* free jobj */
	json_object_put(jobj);

	/* load group detail from /etc/group */
	/* load user detail from /etc/passwd, /etc/shadow */
}

static void flush_sys_group_jsonfile()
{
	int i;
	struct sys_user_group *sys_group = NULL;
	struct json_object *jobj = json_object_new_object();
	struct json_object *groups_obj = json_object_new_object();
	struct json_object *group_obj = NULL;
	struct json_object *group_access_obj = NULL;
	struct json_object *group_privilege_obj = NULL;
	struct json_object *users_obj = NULL;

	/*
		format group to json
	*/
	json_object_object_add(jobj, "active_time", json_object_new_int(active_time));
	json_object_object_add(jobj, "login_errtimes", json_object_new_int(max_login_errtimes));
	list_for_each_entry(sys_group, &sys_group_head, n_list)
	{
		group_obj = json_object_new_object();
		group_access_obj = json_object_new_array();
		group_privilege_obj = json_object_new_array();
		users_obj = json_object_new_object();
		
		for (i = PRIVILEGE_FLAG_USER_MANAGEMENT; i <= PRIVILEGE_FLAG_TRAFFIC_STATISTICS; i++)
		{
			if (__test_bit(i, &sys_group->privilege_flags))
				json_object_array_add(group_privilege_obj, json_object_new_string(privilege_str[i]));
		}
		json_object_object_add(group_obj, "privilege", group_privilege_obj);

		for (i = 0; i <= ACCESS_FLAG_CONSOLE; i++)
		{
			if (__test_bit(i, &sys_group->access_flags))
				json_object_array_add(group_access_obj, json_object_new_string(access_str[i]));
		}
		json_object_object_add(group_obj, "access", group_access_obj);

		json_object_object_add(group_obj, "creator", json_object_new_string(sys_group->creator));
		json_object_object_add(group_obj, "createtime", json_object_new_int64(sys_group->createtime));
		if (sys_group->comment)
			json_object_object_add(group_obj, "comment", json_object_new_string(sys_group->comment));

		users_json_init(sys_group, users_obj);
		json_object_object_add(group_obj, "users", users_obj);

		json_object_object_add(groups_obj, sys_group->groupname, group_obj);
	}

	json_object_object_add(jobj, "groups", groups_obj);
	json_object_to_file(GAP_SYS_GROUP_FILE, jobj);

	json_object_put(jobj);
}

/*
*passwd must be formed by letter, digit, special character ~!@#$%^&*()-_+, and length must be 6-16
*/
static int check_passwd(const char *passwd)
{
	const char *p = NULL;
	int letter = 0;
	int digit = 0;
	int special_character = 0;

	if (strlen(passwd) < 6 || strlen(passwd) > 16)
		return 0;

	for (p = passwd; *p != '\0'; p++)
	{
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))
			letter = 1;
		else if (*p >= '0' && *p <= '9')
			digit = 1;
		else if (strchr("~!@#$%^&*()-_+?", *p))
			special_character = 1;
		else
			return 0;
	}

	return (letter && digit && special_character);
}

int account_config_write(struct vty *vty)
{
	vty_out(vty, "login permission ssh %s console %s%s", g_gapcfg->ssh_login_permission ? "enable" : "disable",
		g_gapcfg->console_login_permission ? "enable" : "disable", VTY_NEWLINE);
	return 0;
}

/*
*generate random key, key len scope <8,15>
*/
void generate_random_key(char *salt, int size)
{
	char key[16] = { 0 };
	int key_len = 0;

	key_len = rand() % 8 + 8;
	get_result_by_system(key, sizeof(key), "openssl rand -base64 32");
	key[key_len] = 0;
	snprintf(salt, size, "$6$%s$", key);
}

int64_t get_current_second()
{
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);
	if (tz.tz_minuteswest < 0)
		tv.tv_sec += abs(tz.tz_minuteswest) * 60;
	else
		tv.tv_sec -= abs(tz.tz_minuteswest) * 60;
	return tv.tv_sec;
}


DEFUN(gap_ctl_groupadd,
	gap_ctl_groupadd_cmd,
	"sys-group add .JSON",
	"system group\n"
	"add\n"
	"json string, format: {'name': 'dasfad','access': 'console,ssh,web','desc': 'sdfadgsa',"
	"'privileges': 'usrmgm,device,network,highavailable,configure,rule,audit,traffic'}\n")
{
	int i;
	char *json_str = NULL;
	const char *groupname = NULL;
	const char *desc = NULL;
	struct json_object *json_group = NULL;
	struct json_object *group_name_obj = NULL;
	struct group *gr = NULL;
	struct sys_user_group *sys_group = NULL;

	json_str = argv_concat(argv, argc, 0);
	SCLogInfo("json_str: %s\n", json_str);
	json_group = json_tokener_parse(json_str);

	json_object_object_get_ex(json_group, "name", &group_name_obj);
	groupname = json_object_get_string(group_name_obj);
	SCLogInfo("groupname: %s\n", groupname);
	if (strstr(self->string, "sys-group add"))
	{
		/* check whether groupname has exist */
		gr = getgrnam(groupname);
		if (gr)
		{
			vty_out(vty, "sys-group %s has exist.%s", groupname, VTY_NEWLINE);
			return CMD_SUCCESS;
		}

		sys_group = sys_user_group_new();
		if (!sys_group)
		{
			vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
			return CMD_ERR_NOTHING_TODO;
		}

		strncpy(sys_group->groupname, groupname, sizeof(sys_group->groupname) - 1);
		if (vty->username)
			sys_group->creator = XSTRDUP(MTYPE_TMP, vty->username);
		else
			sys_group->creator = XSTRDUP(MTYPE_TMP, "none");
	}
	else
	{
		sys_group = find_sys_user_group(groupname);
		if (!sys_group)
		{
			vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	sys_group->access_flags = 0;
	sys_group->privilege_flags = 0;
	json_object_object_foreach(json_group, key, val)
	{
		if (!strcmp(key, "access"))
		{
			for (i = 0; i < json_object_array_length(val); i++)
				access_str2flags(&sys_group->access_flags, json_object_get_string(json_object_array_get_idx(val, i)));
		}
		else if (!strcmp(key, "privileges"))
		{
			for (i = 0; i < json_object_array_length(val); i++)
				privilege_str2flags(&sys_group->privilege_flags, json_object_get_string(json_object_array_get_idx(val, i)));
		}
		else if (!strcmp(key, "desc"))
		{
			if (strlen(json_object_get_string(val)))
				desc = json_object_get_string(val);
			SCLogInfo("desc: %s\n", desc);
		}
	}

	gr = getgrnam(groupname);
	if (!gr)
	{
		cmd_system_novty_arg("groupadd %s", groupname);
		//sys_group->createtime = time(NULL);
		sys_group->createtime = get_current_second();
	}

	SCLogInfo("access_flags: 0x%lx\n", sys_group->access_flags);
	SCLogInfo("privilege_flags: 0x%lx\n", sys_group->privilege_flags);

	if (sys_group->comment)
		XFREE(MTYPE_TMP, sys_group->comment);
	if (desc && strlen(desc))
		sys_group->comment = XSTRDUP(MTYPE_TMP, desc);

	if (strstr(self->string, "sys-group add"))
		list_add(&sys_group->n_list, &sys_group_head);
	flush_sys_group_jsonfile();

	XFREE(MTYPE_TMP, json_str);
	json_object_put(json_group);
	return CMD_SUCCESS;
}

ALIAS(gap_ctl_groupadd,
	gap_ctl_groupedit_cmd,
	"sys-group edit .JSON",
	"system group\n"
	"edit\n"
	"json string, format: {'name': 'dasfad','access': 'console,ssh,web','desc': 'sdfadgsa',"
	"'privileges': 'usrmgm,device,network,highavailable,configure,rule,audit,traffic'}\n");

DEFUN(gap_ctl_groupdel,
	gap_ctl_groupdel_cmd,
	"sys-group delete GROUPNAME",
	"sys-group\n"
	"delete\n"
	"group name\n")
{
	const char *groupname = argv[0];
	struct group *gr = NULL;
	struct sys_user_group *sys_group = NULL;

	sys_group = find_sys_user_group(groupname);
	gr = getgrnam(groupname);
	if (!sys_group || !gr)
	{
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	del_sys_user_group(sys_group);

	flush_sys_group_jsonfile();
	flush_access_conf_file();

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_useradd,
	gap_ctl_useradd_cmd,
	"sys-user add USERNAME group GROUPNAME (enable|disable) {password PWD | mindays WORD | maxdays WORD | warndays WORD | expiredate WORD | desc .LINE}",
	"sys-user\n"
	"add\n"
	"username\n"
	"group\n"
	"groupname\n"
	"disable\n"
	"enable\n"
	"password\n"
	"password value\n"
	"min # of days between password changes\n"
	"measured in days\n"
	"max # of days between password changes\n"
	"measured in days\n"
	"days before password expires to warn user to change it\n"
	"measured in days\n"
	"date when account expires\n"
	"measured in days since 1970-01-01 00:00:00 +0000 (UTC) or in the format YYYY-MM-DD\n"
	"descryption\n"
	"descryption value\n")
{
	int ret;
	uint32_t len;
	char cmd[1024] = { 0 };
	char *en_passwd = NULL;
	char salt[32] = { 0 };
	struct passwd *passwd;
	struct sys_user *sys_user = NULL;
	struct sys_user_group *sys_group = NULL;

	generate_random_key(salt, 32);

	sys_group = find_sys_user_group(argv[1]);
	if (!sys_group)
	{
		SCLogInfo("usergroup %s not exist\n", argv[1]);
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	/* check weak passwd */
	if (argv[3] && !check_passwd(argv[3]))
	{
		vty_result(ERR_CODE_PARAMERROR, ERR_CODE_PARAMERROR_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	if (strstr(self->string, "sys-user add"))
	{
		/* check whether user has exist */
		passwd = getpwnam(argv[0]);
		if (passwd || find_sys_user(argv[1], argv[0]))
		{
			vty_result(ERR_CODE_EXIST, ERR_CODE_EXIST_DESC);
			return CMD_ERR_NOTHING_TODO;
		}

		sys_user = sys_user_new();
		if (!sys_user)
		{
			vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
			return CMD_ERR_NOTHING_TODO;
		}

		if (argv[8])
		{
			sys_user->comment = argv_concat(argv, argc, 8);
		}

		if (!passwd)
		{
			sys_user->createtime = time(NULL);
			cmd_system_novty_arg("useradd %s -G %s -s /usr/bin/vtysh", argv[0], argv[1]);
		}

		strncpy(sys_user->username, argv[0], sizeof(sys_user->username) - 1);
		if (vty->username)
			strncpy(sys_user->creator, vty->username, sizeof(sys_user->creator) - 1);
		else
			strncpy(sys_user->creator, "none", sizeof(sys_user->creator) - 1);
		sys_user->group = sys_group;
		list_add(&sys_user->n_list, &sys_group->users);
	}
	else
	{
		sys_user = find_sys_user(NULL, argv[0]);
		if (!sys_user)
		{
			SCLogInfo("user %s not exist\n", argv[0]);
			vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
			return CMD_ERR_NOTHING_TODO;
		}

		if (argv[8])
		{
			if (sys_user->comment)
				XFREE(MTYPE_TMP, sys_user->comment);
			sys_user->comment = argv_concat(argv, argc, 8);
		}

		/* modify sys-group user belong to */
		if (strcmp(sys_user->group->groupname, argv[1]))
		{
			list_del(&sys_user->n_list);
			sys_user->group = sys_group;
			list_add(&sys_user->n_list, &sys_group->users);
		}
	}

	if (strcmp(argv[2], "enable") == 0)
		sys_user->user_enable = 1;
	else
		sys_user->user_enable = 0;

	len = snprintf(cmd, sizeof(cmd), "usermod %s", argv[0]);

	if (argv[3])
	{
		en_passwd = crypt(argv[3], salt);
		len += snprintf(cmd + len, sizeof(cmd) - len, " -p '%s'", en_passwd);
		if (en_passwd)
			cmd_system_novty(cmd);
	}

	memset(cmd, 0, sizeof(cmd));
	len = 0;

	len = snprintf(cmd, sizeof(cmd), "%s", "chage");
	if (argv[4])
		len += snprintf(cmd + len, sizeof(cmd) - len, " -m %s", argv[4]);
	if (argv[5])
		len += snprintf(cmd + len, sizeof(cmd) - len, " -M %s", argv[5]);
	if (argv[6])
		len += snprintf(cmd + len, sizeof(cmd) - len, " -W %s", argv[6]);
	if (argv[7])
		len += snprintf(cmd + len, sizeof(cmd) - len, " -E %s", argv[7]);
	snprintf(cmd + len, sizeof(cmd) - len, " %s", argv[0]);
	if (len > strlen("chage"))
	{
		ret = cmd_system_novty(cmd);
		if (ret != 0)
		{
			vty_result(ERR_CODE_SYSERROR, ERR_CODE_SYSERROR_DESC);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	flush_sys_group_jsonfile();
	flush_access_conf_file();

	return CMD_SUCCESS;
}

ALIAS(gap_ctl_useradd,
	gap_ctl_useredit_cmd,
	"sys-user edit USERNAME group GROUPNAME (enable|disable) {password PWD | mindays WORD | maxdays WORD | warndays WORD | expiredate WORD | desc .LINE}",
	"sys-user\n"
	"edit\n"
	"username\n"
	"group\n"
	"groupname\n"
	"enable\n"
	"disable\n"
	"password\n"
	"password value\n"
	"min # of days between password changes\n"
	"measured in days\n"
	"max # of days between password changes\n"
	"measured in days\n"
	"days before password expires to warn user to change it\n"
	"measured in days\n"
	"date when account expires\n"
	"measured in days since 1970-01-01 00:00:00 +0000 (UTC) or in the format YYYY-MM-DD\n"
	"descryption\n"
	"descryption value\n");

DEFUN(gap_ctl_userdel,
	gap_ctl_userdel_cmd,
	"sys-user delete USERNAME",
	"sys-user\n"
	"delete\n"
	"user name\n"
	"sys-group\n"
	"groupname\n")
{
	struct sys_user *sys_user = NULL;

	sys_user = find_sys_user(NULL, argv[0]);
	if (!sys_user)
	{
		vty_result(ERR_CODE_NOTFOUND, ERR_CODE_NOTFOUND_DESC);
		return CMD_ERR_NOTHING_TODO;
	}

	if( (strcmp(sys_user->username, "admin") == 0) || 
		(strcmp(sys_user->username, vty->username) == 0) )
	{
		vty_result(ERR_CODE_PERMISSION_DENIED, ERR_CODE_PERMISSION_DENIED_DESC);
		return CMD_ERR_NOTHING_TODO;	
	}
	del_sys_user(sys_user);

	flush_sys_group_jsonfile();
	flush_access_conf_file();

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_user_password,
	gap_ctl_user_password_cmd,
	"user-password PWD",
	"change current user password\n"
	"password value\n")
{
	struct spwd *spw = NULL;
	char *en_passwd = NULL;
	char salt[32] = { 0 };
	time_t today;

	if (!vty->username)
	{
		vty_out(vty, "no user login%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	spw = getspnam(vty->username);
	today = time(NULL) / (3600 * 24);
	SCLogInfo("spw->sp_min: %d\n", spw->sp_min);
	SCLogInfo("today: %d\n", today);
	SCLogInfo("spw->sp_lstchg: %d\n", spw->sp_lstchg);
	if (spw->sp_min && ((today - spw->sp_lstchg) <= spw->sp_min))
	{
		vty_out(vty, "forbid to change passwd%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	if (!check_passwd(argv[0]))
	{
		vty_out(vty, "weak password%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	generate_random_key(salt, 32);
	en_passwd = crypt(argv[0], salt);
	cmd_system_novty_arg("usermod %s -p '%s'", vty->username, en_passwd);
	return CMD_SUCCESS;
}

DEFUN(gap_ctl_login_args,
	gap_ctl_login_args_cmd,
	"user-login {active-time TIME | errtimes TIMES}",
	"user-login\n"
	"active time\n"
	"time value, in minites\n"
	"max login error times\n"
	"value\n")
{
	if (argv[0])
		active_time = atoi(argv[0]);
	if (argv[1])
		max_login_errtimes = atoi(argv[1]);
	if (argv[0] || argv[1])
		flush_sys_group_jsonfile();
	return CMD_SUCCESS;
}

DEFUN(gap_ctl_sysuser_view,
	gap_ctl_sysuser_view_cmd,
	"show sys-user {username NAME}",
	SHOW_STR
	"system user\n"
	"user name\n")
{
	struct json_object *jobj = json_object_from_file(GAP_SYS_GROUP_FILE);
	struct json_object *user_obj = NULL;

	if (!jobj)
		return CMD_SUCCESS;

	if (!argv[0])
		vty_out(vty, "%s%s", json_object_to_json_string_ext(jobj, 0), VTY_NEWLINE);
	else
	{
		json_object_object_foreach(jobj, key1, value1)
		{
			if (!strcmp(key1, "groups"))
			{
				json_object_object_foreach(value1, key2, value2)
				{
					json_object_object_foreach(value2, group_key, group)
					{
						if (!strcmp(group_key, "users"))
						{
							json_object_object_foreach(group, user_key, user)
							{
								if (!strcmp(user_key, argv[0]))
								{
									json_object_object_foreach(user, key, value)
									{
										if (!strcmp(key, "creator"))
										{
											/*if (vty->username && strcmp(vty->username, json_object_get_string(value))) {
												json_object_put(jobj);
												return CMD_SUCCESS;
											}*/
											break;
										}
									}
									S2J_SET_STRING(user, "groupname", key2);
									vty_out(vty, "%s%s", json_object_to_json_string_ext(user, 0), VTY_NEWLINE);
									json_object_put(jobj);
									return CMD_SUCCESS;
								}
							}
						}
					}
				}
			}
		}
	}

	/* free jobj */
	json_object_put(jobj);

	return CMD_SUCCESS;
}

DEFUN(gap_ctl_login,
	gap_ctl_login_cmd,
	"login permission {ssh (enable|disable) |console (enable|disable)}",
	"login\n"
	"permission\n"
	"ssh\n"
	"enable login permission\n"
	"disable login permission\n"
	"console\n"
	"enable login permission\n"
	"disable login permission\n")
{
	if (argv[0])
	{
		if (strncmp(argv[0], "enable", 6) == 0)
			g_gapcfg->ssh_login_permission = 1;
		else
			g_gapcfg->ssh_login_permission = 0;
	}

	if (argv[1])
	{
		if (strncmp(argv[1], "enable", 6) == 0)
			g_gapcfg->console_login_permission = 1;
		else
			g_gapcfg->console_login_permission = 0;
	}

	flush_access_conf_file();
	return CMD_SUCCESS;
}

DEFUN(gap_ctl_login_permission_view,
	gap_ctl_login_permission_view_cmd,
	"show login permission",
	SHOW_STR
	"ssh and console login\n"
	"permission\n")
{
	vty_out(vty, "serial:%s%s", g_gapcfg->console_login_permission ? "enable" : "disable", VTY_NEWLINE);
	vty_out(vty, "ssh    : %s%s", g_gapcfg->ssh_login_permission ? "enable" : "disable", VTY_NEWLINE);
	return CMD_SUCCESS;
}

void add_ipt_allowed_ip_port_cb(struct access_list *access, struct filter *filter)
{
	struct filter_zebra *zfilter = NULL;
	char cmdbuf[256] = { 0 };
	char comment[64] = { 0 };
	char ip[32] = { 0 };
	int rule_id;

	if (!filter)
		return;

	zfilter = &filter->u.zfilter;
	if (strcmp(zfilter->proto, "tcp") && strcmp(zfilter->proto, "udp"))
		return;

	snprintf(comment, sizeof(comment), "%s:%d%s", prefix2str(&zfilter->prefix, ip, sizeof(ip)), zfilter->port, zfilter->proto);
	/* if iptable rule has been added, return */
	rule_id = get_rule_number(comment);
	if (rule_id)
		return;

	snprintf(cmdbuf, sizeof(cmdbuf), "iptables -w -A DEFEND -p %s --source %s --destination-port %d -m "
		"comment --comment %s -j %s",
		zfilter->proto,
		prefix2str(&zfilter->prefix, ip, sizeof(ip)),
		zfilter->port,
		comment,
		(filter->type == FILTER_DENY) ? "DROP" : "ACCEPT");
	SCLogInfo("iptable cmd: %s\n", cmdbuf);
	cmd_system_novty(cmdbuf);
}

void del_ipt_allowed_ip_port(struct filter *filter)
{
	struct filter_zebra *zfilter = NULL;
	char cmdbuf[256] = { 0 };
	char comment[64] = { 0 };
	char ip[32] = { 0 };
	int rule_id;

	zfilter = &filter->u.zfilter;
	if (strcmp(zfilter->proto, "tcp") && strcmp(zfilter->proto, "udp"))
		return;

	snprintf(comment, sizeof(comment), "%s:%d%s", prefix2str(&zfilter->prefix, ip, sizeof(ip)), zfilter->port, zfilter->proto);
	snprintf(cmdbuf, sizeof(cmdbuf), "iptables -w -D DEFEND -p %s --source %s --destination-port %d -m "
		"comment --comment %s -j %s",
		zfilter->proto,
		prefix2str(&zfilter->prefix, ip, sizeof(ip)),
		zfilter->port,
		comment,
		(filter->type == FILTER_DENY) ? "DROP" : "ACCEPT");
	SCLogInfo("iptable cmd: %s\n", cmdbuf);

	/* if there is other same iptable rule, delete it again */
	while ((rule_id = get_rule_number(comment)) != 0)
		cmd_system_novty(cmdbuf);
}

void del_ipt_allowed_ip_port_cb(struct access_list *access, struct filter *filter)
{
	if (filter)
	{
		del_ipt_allowed_ip_port(filter);
	}
	else
	{
		for (filter = access->head; filter; filter = filter->next)
		{
			del_ipt_allowed_ip_port(filter);
		}
	}
}

void account_conf_cmd_init(void)
{
	install_element(CONFIG_NODE, &gap_ctl_groupadd_cmd);
	install_element(CONFIG_NODE, &gap_ctl_groupedit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_groupdel_cmd);
	install_element(CONFIG_NODE, &gap_ctl_useradd_cmd);
	install_element(CONFIG_NODE, &gap_ctl_useredit_cmd);
	install_element(CONFIG_NODE, &gap_ctl_userdel_cmd);
	install_element(CONFIG_NODE, &gap_ctl_login_args_cmd);
	install_element(CONFIG_NODE, &gap_ctl_login_cmd);
	install_element(ENABLE_NODE, &gap_ctl_user_password_cmd);

	install_ignore_log_cmd(&gap_ctl_user_password_cmd);
}

void account_show_cmd_init(unsigned int machine)
{
	if (machine == inner_machine || machine == outer_machine)
	{
		install_element(VIEW_NODE, &gap_ctl_sysuser_view_cmd);
		install_element(ENABLE_NODE, &gap_ctl_sysuser_view_cmd);

		install_element(VIEW_NODE, &gap_ctl_login_permission_view_cmd);
		install_element(ENABLE_NODE, &gap_ctl_login_permission_view_cmd);
	}
}

void account_cmd_init(void)
{
	INIT_LIST_HEAD(&sys_group_head);

	load_sys_group_jsonfile();
	flush_access_conf_file();

	access_list_add_hook(add_ipt_allowed_ip_port_cb);
	access_list_delete_hook(del_ipt_allowed_ip_port_cb);
}

void account_cmd_exit(void)
{
	struct sys_user_group *group = NULL;
	struct sys_user_group *groupn = NULL;

	list_for_each_entry_safe(group, groupn, &sys_group_head, n_list)
	{
		del_sys_user_group(group);
	}
}

