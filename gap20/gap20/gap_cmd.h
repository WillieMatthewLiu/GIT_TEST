#ifndef _GAP_CMD_H
#define _GAP_CMD_H
#include "util-list.h"
#include "util-mem.h"
#include "oscall.h"

#define DEFAULT_PGINDEX "1"
#define DEFAULT_PGSIZE "10"
#define DEFAULT_PGSIZE_INT 10

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((unsigned char*)(x))[0],((unsigned char*)(x))[1],((unsigned char*)(x))[2],((unsigned char*)(x))[3],((unsigned char*)(x))[4],((unsigned char*)(x))[5]

#define INTERFACE_NUM 8
#define MAX_RT  255
#define MAX_IPRANGE_SIZE 64
#define NAME_LEN 32
#define PASSWD_LEN 128
#define SID_LEN 128
#define IPV4_LEN 16   /* eg: "255.255.255.0" */
#define USER_IP_LEN IPV4_LEN*2
#define MAC_LEN 6
#define SIGN_LEN 4    /* eg: "0" */
#define PROTO_LEN 8   /* eg: "HTTP" */
#define PROTO_NUM 4
#define IFNAME_LEN 8  /* eg: "MGMT" */
#define PHYNAME_LEN 8 /* eg: "eth1" */
#define IPSET_LEN IPV4_LEN*MAX_IPRANGE_SIZE
#define PORT_LEN 8   /* eg: "65535" */
#define PORT_NUM 24

#define KEY1 "loggingswitch"

enum operate {
	op_add,
	op_edit,
	op_del,
	op_rename,
	op_max
};

struct ip_range
{
	unsigned int first_ip;
	unsigned int second_ip;
	int suffix;
	int type; /*  1(single), 2(range), 3(scope) */
};

#endif 
