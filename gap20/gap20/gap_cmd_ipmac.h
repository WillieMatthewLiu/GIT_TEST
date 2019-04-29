#ifndef _GAP_CMD_IPMAC_H
#define _GAP_CMD_IPMAC_H
#include "util-list.h"
#include "gap_cmd.h"

struct gap_ipmac_rule
{
	struct list_head n_list;
	struct list_head l_list;/* 链接到查询链表上 */
	char device[NAME_LEN + 1]; /* name of device */
	unsigned int ip;
	unsigned char mac[MAC_LEN];
	char action[SIGN_LEN]; /*b(blocked), w(warn) */
	int enable;
};

int check_ipmac(unsigned int ip, unsigned char *mac, char rule[], int len);
void ipmac_conf_cmd_init(void);
void ipmac_show_cmd_init(unsigned int machine);
void ipmac_init(void);
void ipmac_exit(void);

#endif 
