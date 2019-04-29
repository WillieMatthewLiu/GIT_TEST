#pragma once


struct _arphdr {
	u_short      ar_hrd;     /* format of hardware address   */
	u_short      ar_pro;     /* format of protocol address   */
	u_char       ar_hln;     /* length of hardware address   */
	u_char       ar_pln;     /* length of protocol address   */
	u_short      ar_op;      /* ARP opcode (command)     */

	u_char       ar_sha[6];   /* sender hardware address  */
	u_char       ar_sip[4];      /* sender IP address        */
	u_char       ar_tha[6];   /* target hardware address  */
	u_char       ar_tip[4];      /* target IP address        */
};

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/icmp.h>
