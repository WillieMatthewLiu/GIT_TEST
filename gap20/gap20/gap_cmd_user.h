#ifndef _GAP_CMD_USER_H
#define _GAP_CMD_USER_H
#include "util-list.h"
#include "util-mem.h"
#include "oscall.h"
#include "gap_ctl_conf.h"
#include "gap_cmd.h"
#include "gap_cmd_group.h"

#define GAP_USER_TAB_BITS 7
#define GAP_USER_TAB_SIZE (1 << GAP_USER_TAB_BITS)
#define GAP_USER_TAB_MASK (GAP_USER_TAB_SIZE - 1)

struct port_range
{
	unsigned short first_port;
	unsigned int second_port;
	int type; /*  1(single), 2(range)*/
};

struct gap_user_rule
{
	struct list_head n_list;
	struct list_head g_list;/* 链接到用户组上 */
	struct list_head l_list;/* 链接到查询链表上 */
	char username[NAME_LEN + 1];
	struct gap_group_rule* group;
	char strip[USER_IP_LEN];/*192.168.1.1 or 192.168.1.1-192.168.1.10*/
	unsigned int first_ip;
	unsigned int second_ip;
	char port[PORT_LEN*PORT_NUM];
	struct port_range pt[PORT_NUM];
	int pt_num;
	unsigned char mac[MAC_LEN];
	int level;/*		"0: Top Secret 1: Secret 2: Confidential 3: Unclassified"*/
	int enable; /* 1启用 0禁用 */
	int type; /*1加密卡用户，0普通用户*/
};

#endif 
