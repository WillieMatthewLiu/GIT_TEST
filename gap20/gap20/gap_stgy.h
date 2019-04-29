#ifndef _GAP_ARBITER_STGY_H_
#define _GAP_ARBITER_STGY_H_
#include "svrid.h"
#include "gap_ctl.h"

struct acl_data
{
	char route[NAME_LEN];
	char inif[IFNAME_LEN];
	char outif[IFNAME_LEN];
	char c_smac[NAME_LEN];
	char c_sip[IPV4_LEN];
	char c_sport[PORT_LEN];
	char c_dip[IPV4_LEN];
	char c_dport[PORT_LEN];
	int src_level;
	int dst_level;
	unsigned char smac[MAC_LEN];	/* source MAC */
	unsigned int sip;				/* source ip */
	unsigned short sport;			/* source port */
	unsigned int dip;				/* dest ip */
	unsigned short dport;			/* dest port */
	char user[NAME_LEN];			/* user name */
	int dir;						/* Data direction 0x1表示外到内，0x2表示内到外 0x3表示双向 */
	uint32_t svrid;

	char groupname[NAME_LEN];
	struct gap_group_rule *group;
};

int get_acl_data(char *buf, struct acl_data *ad);
int stgy_check_rule(void *obj, char rule[], int len);

#endif

