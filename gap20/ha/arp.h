/*
 */

#ifndef _HA_ARP_H
#define _HA_ARP_H

 /* system includes */
#include <net/ethernet.h>
#include <net/if_arp.h>

/* local includes */

/* local definitions */
#define ETHERNET_HW_LEN		6
#define IPPROTO_ADDR_LEN	4

/* types definition */
typedef struct _arphdr
{
	unsigned short int	ar_hrd;	/* Format of hardware address.  */
	unsigned short int	ar_pro;	/* Format of protocol address.  */
	unsigned char		ar_hln;	/* Length of hardware address.  */
	unsigned char		ar_pln;	/* Length of protocol address.  */
	unsigned short int	ar_op;	/* ARP opcode (command).  */

	/* Ethernet looks like this : This bit is variable sized however...  */
	unsigned char		__ar_sha[ETH_ALEN];	/* Sender hardware address.  */
	unsigned char		__ar_sip[4];		/* Sender IP address.  */
	unsigned char		__ar_tha[ETH_ALEN];	/* Target hardware address.  */
	unsigned char		__ar_tip[4];		/* Target IP address.  */
} arphdr_t;

/* Global vars exported */
extern int garp_fd;

/* prototypes */
extern void gratuitous_arp_init(void);
extern void gratuitous_arp_close(void);
extern int send_gratuitous_arp(struct interface*, struct prefix_ipv4*);

#endif