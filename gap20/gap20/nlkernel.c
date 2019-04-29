
#include "app_common.h"
#include "nlkernel.h"
#include "nlkernelmsg.h"
#include "oscall.h"

static evutil_socket_t g_capsockets[2];
static pthread_t g_capthread;
static int g_capthreadrunning = 0;

#include <linux/netlink.h> 
#include <linux/socket.h> 
#include "gapconfig.h"
#define NETLINK_GAP 29 
#define MAX_PAYLOAD 10240

evutil_socket_t g_nlfd = 0;
struct nlmsghdr *g_recv_nlhdr = NULL;
void* cap_thread(void *args)
{
	g_capthreadrunning = 1;

	struct sockaddr_nl dest_addr = { 0 };
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = getpid();
	dest_addr.nl_groups = 0;

	g_recv_nlhdr->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	g_recv_nlhdr->nlmsg_pid = getpid();
	g_recv_nlhdr->nlmsg_flags = 0;

	struct iovec iov;
	iov.iov_base = (void *)g_recv_nlhdr;
	iov.iov_len = g_recv_nlhdr->nlmsg_len;

	struct msghdr msg = { 0 };
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	SCLogInfo("nlkernel cap_thread running");

	while (1)
	{
		int n = recvmsg(g_nlfd, &msg, 0);

		struct nl_kerne_report_msg *knmsg = NLMSG_DATA(g_recv_nlhdr);
		size_t len = knmsg->len + sizeof(*knmsg);

		struct nl_kerne_report_msg *dupmsg = SCMalloc(len);
		if (dupmsg == NULL)
			continue;
		memcpy(dupmsg, knmsg, len);

		int ret = send(g_capsockets[1], (char*)&dupmsg, sizeof(dupmsg), 0);
		if (ret == -1)
		{
			SCLogInfo("pktcapturer, onpacket, dropped...");
			SCFree(dupmsg);
		}
	}

	g_capthreadrunning = 0;

	return NULL;
}

evutil_socket_t nlkernel_init()
{
	int ret, ok = 0;
	do
	{
		g_nlfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GAP);
		if (g_nlfd == -1)
			break;

		ret = evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, g_capsockets);
		if (ret != 0)
			break;

		ret = evutil_make_socket_nonblocking(g_capsockets[0]);
		if (ret != 0)
			break;

		ret = evutil_make_socket_nonblocking(g_capsockets[1]);
		if (ret != 0)
			break;

		g_recv_nlhdr = SCMalloc(NLMSG_SPACE(MAX_PAYLOAD));
		if (g_recv_nlhdr == NULL)
			break;
		memset(g_recv_nlhdr, 0, NLMSG_SPACE(MAX_PAYLOAD));

		ret = pthread_create(&g_capthread, NULL, cap_thread, NULL);
		if (ret != 0)
			break;
#ifdef USER_MEM_ALLOC
		ThreadMemInit("", g_capthread);
#endif

		int netlink_send(unsigned int pid, const void *buffer, size_t len);
		struct nl_kernel_msg msg = { 0 };
		msg.op = NLOP_REMOVE;
		netlink_send(getpid(), &msg, sizeof(msg));

		ok = 1;
	} while (0);

	if (ok == 0)
	{
		SCLogInfo("ok ==0");
		
		if (g_recv_nlhdr != NULL)
			SCFree(g_recv_nlhdr);

		closesocket(g_capsockets[0]);
		closesocket(g_capsockets[1]);
		closesocket(g_nlfd);
		g_capsockets[0] = -1;
		g_capsockets[1] = -1;
		g_nlfd = -1;
	}
	return g_capsockets[0];
}

int netlink_send(unsigned int pid, const void *buffer, size_t len)
{
	if (len > NLMSG_SPACE(MAX_PAYLOAD))
		return -1;

	struct sockaddr_nl src_addr = { 0 };
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = pid;   /* self pid */
	src_addr.nl_groups = 0;  /* not in mcast groups */
	bind(g_nlfd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	struct sockaddr_nl dest_addr = { 0 };
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	struct nlmsghdr *send_nlhdr = SCMalloc(NLMSG_SPACE(len));
	memset(send_nlhdr, 0, NLMSG_SPACE(len));
	send_nlhdr->nlmsg_len = NLMSG_SPACE(len);
	send_nlhdr->nlmsg_pid = pid;
	send_nlhdr->nlmsg_flags = 0;

	if (buffer != NULL)
		memcpy(NLMSG_DATA(send_nlhdr), buffer, len);

	struct iovec iov;
	iov.iov_base = (void*)send_nlhdr;
	iov.iov_len = send_nlhdr->nlmsg_len;

	struct msghdr msg = { 0 };
	msg.msg_name = (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	int nsends = sendmsg(g_nlfd, &msg, 0);
	SCFree(send_nlhdr);
	if (nsends <= 0)
		return -1;
	return 0;
}
// 
// int nlkernel_sendmsg(struct nl_kernel_msg *msg)
// {
// 	SCLogInfo("send msg tokernel, type: %d, op: %d", msg->type, msg->op);
// 	return netlink_send(getpid(), msg, sizeof(*msg));
// }

int nlkernel_sendmsg(struct nl_kernel_msg *msg)
{
	int fd = 0;
	int ok = 0, ret;
	do
	{
		fd = open(GAP_CONTROL_NAME, O_RDWR);
		if (fd <= 0)
			break;

		ret = ioctl(fd, GAP_CMD_INFO, msg);
		if (ret != 0)
			break;

		close(fd);
		ok = 1;
	} while (0);

	SCLogInfo("nlkernel_sendmsg, type: %d, op: %d, isok: %d", msg->type, msg->op, ok);

	if (ok == 0)
	{
		close(fd);
		return -1;
	}
	return 0;
}

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
int nlkernel_sendpkt(const char *ethname, const void *packet, size_t len)
{
	static evutil_socket_t fds[MAX_ETH_COUNT] = { 0 };
	static struct sockaddr_ll addrs[MAX_ETH_COUNT];

	struct interface *ifp = if_lookup_by_name(ethname);
	if (ifp == NULL)
		return -1;

	int n = ifp->ifindex;
	if (n == -1 || n >= MAX_ETH_COUNT)
		return -1;

	if (fds[n] == 0)
	{
		fds[n] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

		struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifp->name, sizeof(ifr.ifr_name));
		ioctl(fds[n], SIOCGIFINDEX, &ifr);

		memset(&addrs[n], 0, sizeof(addrs[n]));
		addrs[n].sll_family = AF_PACKET;
		addrs[n].sll_protocol = htons(ETH_P_ALL);
		addrs[n].sll_ifindex = ifr.ifr_ifindex;
	}
	if (fds[n] <= 0)
		return -1;

	int ret = sendto(fds[n], (char*)packet, (int)len, 0, (struct sockaddr *)&addrs[n], sizeof(addrs[n]));
	if (ret == -1)
	{
		SCLogInfo("send pkt to %s failed, ret: %d, errno: %d", ethname, ret, errno);
		return -1;
	}
	return 0;
}

uint32_t nlkernel_getuidbyaddr(uint32_t srcip, uint16_t srcport, uint32_t localip, uint16_t localport, uint8_t *mac)
{
	int ret;
	struct nl_kernel_msg msg = { 0 };
	msg.type = NLCMD_UID;
	msg.op = NLOP_GET;
	msg.data.conn.sip = srcip;
	msg.data.conn.sport = srcport;
	msg.data.conn.dip = localip;
	msg.data.conn.dport = localport;
	msg.data.conn.protocol = IPPROTO_TCP;
	msg.data.conn.uid = 0;
	ret = nlkernel_sendmsg(&msg);
	if (ret != 0)
		return 0;
	memcpy(mac, msg.data.conn.mac, 6);
	return msg.data.conn.uid;
}


uint32_t nlkernel_addenc(uint32_t srcip, uint16_t srcport, uint32_t localip, uint16_t localport, uint32_t uid)
{
	int ret;
	struct nl_kernel_msg msg = { 0 };
	msg.type = NLCMD_ADDENC;
	msg.op = NLOP_ADD;
	msg.data.conn.sip = localip;
	msg.data.conn.sport = localport;
	msg.data.conn.dip = srcip;
	msg.data.conn.dport = srcport;
	msg.data.conn.protocol = IPPROTO_TCP;
	msg.data.conn.uid = uid;
	ret = nlkernel_sendmsg(&msg);
	if (ret != 0)
		return -1;
	return msg.data.conn.uid;
}

int nlkernel_free()
{
	if (g_nlfd > 0)
		closesocket(g_nlfd);

	if (g_capthreadrunning == 1)
		pthread_kill(g_capthread, 0);
	if (g_capsockets[0] > 0)
		closesocket(g_capsockets[0]);
	if (g_capsockets[1] > 0)
		closesocket(g_capsockets[1]);
	if (g_recv_nlhdr != NULL)
		SCFree(g_recv_nlhdr);

	g_capsockets[0] = -1;
	g_capsockets[1] = -1;
	g_nlfd = -1;
	return 0;
}

void nl_arp_enable()
{
	int fd = 0;
	int ok = 0, ret;
	fd = open(GAP_CONTROL_NAME, O_RDWR);
	if (fd <= 0)
		return;

	ret = ioctl(fd, GAP_CMD_ARP_REJECT, &ok);
	ret = ret;

	close(fd);


	return;
}

void nl_arp_disable()
{
	int fd = 0;
	int ok = 1, ret;
	fd = open(GAP_CONTROL_NAME, O_RDWR);
	if (fd <= 0)
		return;

	ret = ioctl(fd, GAP_CMD_ARP_REJECT, &ok);
	ret = ret;

	close(fd);


	return;
}

uint32_t nlkernel_clearconfig()
{
	int fd = 0;
	int ok = 0, ret;
	fd = open(GAP_CONTROL_NAME, O_RDWR);
	if (fd <= 0)
		return -1;

	ret = ioctl(fd, GAP_CMD_CLEAR_CONFIG, &ok);
	ret = ret;

	close(fd);
	return ok;
}

void nlkernel_encrypt_enable()
{
	int fd = 0;
	int ok = 1, ret;
	fd = open(GAP_CONTROL_NAME, O_RDWR);
	if (fd <= 0)
		return;

	ret = ioctl(fd, GAP_CMD_ENABLE_ENCRYPT, &ok);
	ret = ret;

	close(fd);
}

void nlkernel_encrypt_disable()
{
	int fd = 0;
	int ok = 0, ret;
	fd = open(GAP_CONTROL_NAME, O_RDWR);
	if (fd <= 0)
		return;

	ret = ioctl(fd, GAP_CMD_ENABLE_ENCRYPT, &ok);
	ret = ret;

	close(fd);
}
