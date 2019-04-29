 /* system includes */
#include <unistd.h>
#include <netpacket/packet.h>

#include "zebra.h"
#include "if.h"
#include "prefix.h"

#include "app_common.h"
/* local includes */
#include "arp.h"

/* global vars */
char garp_buffer[sizeof(arphdr_t) + ETHER_HDR_LEN + 1] = { 0 };
int garp_fd = -1;

/* Send the gratuitous ARP message */
static int send_arp(struct interface *ifp, struct prefix_ipv4 *p)
{
	struct sockaddr_ll sll;
	int len;

	if (garp_fd < 0)
	{
		gratuitous_arp_init();
	}
		
	/* Build the dst device */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	memcpy(sll.sll_addr, ifp->hw_addr, ETH_ALEN);
	sll.sll_halen = ETHERNET_HW_LEN;
	sll.sll_ifindex = ifp->ifindex;

	/* Send packet */
	len = sendto(garp_fd, garp_buffer, sizeof(arphdr_t) + ETHER_HDR_LEN
		, 0, (struct sockaddr *)&sll, sizeof(sll));
	if (len < 0)
	{
		SCLogInfo("Error sending gratuitous ARP on %s for %s(%s)",
			ifp->name, inet_ntoa(p->prefix), strerror(errno));
	}		
	
	return len;
}

/* Build a gratuitous ARP message over a specific interface */
int send_gratuitous_arp(struct interface *ifp, struct prefix_ipv4 *p)
{
	struct ether_header *eth = (struct ether_header *) garp_buffer;
	arphdr_t *arph = (arphdr_t*)(garp_buffer + ETHER_HDR_LEN);
	char *hwaddr = (char*)ifp->hw_addr;
	int len;

	/* Ethernet header */
	memset(eth->ether_dhost, 0xFF, ETH_ALEN);
	memcpy(eth->ether_shost, hwaddr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	/* ARP payload */
	arph->ar_hrd = htons(ARPHRD_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = ETHERNET_HW_LEN;
	arph->ar_pln = IPPROTO_ADDR_LEN;
	arph->ar_op = htons(ARPOP_REQUEST);
	memcpy(arph->__ar_sha, hwaddr, ETH_ALEN);
	memcpy(arph->__ar_sip, &p->prefix.s_addr, sizeof(struct in_addr));
	memset(arph->__ar_tha, 0xFF, ETH_ALEN);
	memcpy(arph->__ar_tip, &p->prefix.s_addr, sizeof(struct in_addr));

	/* Send the ARP message */
	len = send_arp(ifp, p);

	/* Cleanup room for next round */
	memset(garp_buffer, 0, sizeof(arphdr_t) + ETHER_HDR_LEN);
	return len;
}

/*
 *	Gratuitous ARP init/close
 */
void gratuitous_arp_init(void)
{
	/* Create the socket descriptor */
	garp_fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_RARP));

	if (garp_fd > 0)
	{
		SCLogInfo("Registering gratuitous ARP shared channel");
	}		
	else
	{
		SCLogInfo("Error while registering gratuitous ARP shared channel");
	}		
}

void gratuitous_arp_close(void)
{
	close(garp_fd);
}

void send_link_update(struct interface *ifp, int repeat)
{
	struct listnode *node;
	struct connected *ifc;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc))
	{
		if (ifc->address->family == AF_INET)
		{
			for (int i = 0; i < repeat; i++)
			{
				send_gratuitous_arp(ifp, (struct prefix_ipv4*)ifc->address);
			}				
		}
	}
}