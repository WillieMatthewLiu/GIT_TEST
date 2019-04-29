#ifndef _CMD__COMMON_H_
#define _CMD__COMMON_H_

#include "vector.h"
extern struct host host;
extern vector cmdvec;
extern int board_type;
extern struct vty_chain _vty_base_chain;

#define BOARDTYPE_IN       0
#define BOARDTYPE_OUT      1
#define BOARDTYPE_ARBITER  2
#define ARBITER_DEFAULT_IP_STR "192.168.0.1"
#define INNER_DEFAULT_IP_STR "192.168.0.2"
#define OUTER_DEFAULT_IP_STR "192.168.0.3"
#define SECONDS_PER_MIN    60
#define SECONDS_PER_HOUR   3600
#define SECONDS_PER_DAY    86400

#define RUN_AS_INNER()\
    (board_type == BOARDTYPE_IN)

#define RUN_AS_OUTER()\
    (board_type == BOARDTYPE_OUT)

#define RUN_NOT_AS_INNER()\
    (board_type != BOARDTYPE_IN)

#define BOARDTYPE_STR \
    (RUN_AS_INNER()?"内端机":"外端机")

void cmd_install_node(struct cmd_node *node, int(*func) (struct vty *));
int cmd_system_real(struct vty *vty, char *cmd);
int cmd_system_getout(char* cmdstring, char* buf, int len);
int cmd_system_arg_real(struct vty *vty, char* format, ...);

#define cmd_system(cmd)   	  cmd_system_real(vty, cmd)
#define cmd_system_arg(args...)   cmd_system_arg_real(vty, ##args)
#define cmd_system_novty(cmd)   	  cmd_system_real(NULL, cmd)
#define cmd_system_novty_arg(args...) cmd_system_arg_real(NULL, ##args)

extern int cmd_common_init();
char* is_dpi_add_rule(const char* buffer);
int vty_lock(const char *path);
int vty_unlock(const char *path);
char* vty_setlogin_name(struct vty *vty, char* username);
char *vty_getlogin(struct vty *vty);
void cmd_log_command(struct vty* vty, vector vline, int result);
void cmd_log_command_str(struct vty* vty, char* line, int result);
int get_ssh_login_ip(char* buffer, int len);

struct vty_client
{
	int fd;
	const char *name;
	unsigned int arg;
	char path[256];
};
int get_result_by_system(char* result, int result_len, const char *format, ...);
struct vty_adapter * vty_adapter_init(struct vty_adapter *adpt, char* ip, uint16_t port);
extern void vty_adapter_deinit(struct vty_adapter *adpt);



extern int cmd_get_boardtype();
extern int vty_adapter_run(struct vty *vty, struct vty_adapter* adpt);
extern int vty_chain_base_cb(struct vty *vty, int ret);

#endif
