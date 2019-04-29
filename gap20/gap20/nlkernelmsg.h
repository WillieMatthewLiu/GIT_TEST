#pragma once

enum NETLINK_CMDTYPE
{
	NLCMD_IP,
	NLCMD_PROTO,
	NLCMD_UKEY,
	NLCMD_UID,
	NLCMD_ADDENC
};

enum NETLINK_OPERATOR
{
	NLOP_ADD,
	NLOP_REMOVE,
	NLOP_GET
};

enum NETLINK_REPORTTYPE
{
	NLRPT_NAT,
	NLRPT_PACKET,
	NLRPT_USERID,
};

struct nl_kerne_report_msg
{
	char ifname[16];
	enum NETLINK_REPORTTYPE type;
	uint32_t len;
	char data[0];
};

struct _local_ip_data
{
	char ifname[16];
	uint32_t ip;
};

struct _proto_data
{
	char ifname[16];
	uint32_t layer; /* 2 or 3 */
	uint32_t protocol;/* arp or icmp */
};

struct _ukey_data
{
	uint32_t uid;
	char key[32];
};

struct _conn_data
{
	uint32_t sip;
	uint16_t sport;
	uint32_t dip;
	uint16_t dport;
	uint32_t protocol;
	uint32_t uid;
	uint8_t mac[6];
};

/* 下发内核的消息 */
struct nl_kernel_msg
{
	enum NETLINK_CMDTYPE type;
	enum NETLINK_OPERATOR op;
	union {
		struct _local_ip_data localip;
		struct _proto_data proto;
		struct _ukey_data ukey;
		struct _conn_data conn;
	}data;
};



#define GAP_CONTROL_NAME "/dev/gap_ioctl_file"
#define GAP_CMD_INFO 			('U'<<24 | 'R'<<16 | 'L' <<8 | 'A')
#define GAP_CMD_ARP_REJECT      GAP_CMD_INFO+1
#define GAP_CMD_CLEAR_CONFIG    GAP_CMD_INFO+2
#define GAP_CMD_ENABLE_ENCRYPT  GAP_CMD_INFO+3
