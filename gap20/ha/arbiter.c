#include "app_common.h"
#include "ha.h"
#include "ha_init.h"
#include "ha_common.h"

struct arbiter_control {
	int sock;
	struct sockaddr_in dest[2];
	struct event *ev_send;
	struct event *ev_recv;
	int timeout_count;
	uint16_t sequence;
};

struct arbiter_control _arbiter = {};

struct icmphdr {
	uint8_t		type;
	uint8_t		code;
	uint16_t	checksum;
	union {
		struct {
			uint16_t	id;
			uint16_t	sequence;
		} echo;
		uint32_t	gateway;
		struct {
			uint16_t	__unused;
			uint16_t	mtu;
		} frag;
	} un;
};

union icmpbuf {
	struct icmphdr icmp;
	char data[64];
};

static uint16_t CheckSum(uint16_t *buf, int size)
{
	uint16_t cksum = 0;
	while (size > 1)
	{
		cksum += *buf++;
		size -= sizeof(uint16_t);
	}
	if (size)
		cksum += *buf++;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (uint16_t)(~cksum);
}

static union icmpbuf* _create_imcp_pkt(struct arbiter_control *arbiter)
{
	union icmpbuf *buf = SCMalloc(sizeof(union icmpbuf));
	if (!buf)
		return NULL;

	memset(buf, 0, sizeof(union icmpbuf));

	buf->icmp.type = 8;
	buf->icmp.un.echo.id = getpid();
	buf->icmp.un.echo.sequence = arbiter->sequence++;

	buf->icmp.checksum = CheckSum((uint16_t *)buf, sizeof(union icmpbuf) / 2);

	return buf;
}


void _icmp_send(int sock, uint16_t flags, void *arg)
{
	int i;
	int len;
	char data[1024];
	union icmpbuf* buf;
	struct icmphdr *p;
	struct sockaddr addr;
	socklen_t addrlen;
	struct timeval tv = {};
	struct arbiter_control *arbiter = arg;

	tv.tv_sec = 10;

	buf = _create_imcp_pkt(arbiter);
	if (!buf)
		return;
	for (i = 0; i < 2; i++) {
		len = sendto(arbiter->sock, buf->data, 64, 0, (struct sockaddr *)&arbiter->dest[i], sizeof(arbiter->dest[i]));
		if (len < 0)
		{
			HA_LOG_ERROR("%s\n", strerror(errno));
			arbiter->timeout_count++;
			goto END;
		}
		len = recvfrom(arbiter->sock, data, 1024, 0, &addr, &addrlen);
		if (len < 0) {
			HA_LOG_ERROR("%s\n", strerror(errno));
			arbiter->timeout_count++;
			goto END;
		}
		p = (struct icmphdr*)data;
	}
END:
	if (arbiter->timeout_count > 10)
	{
		/* timeout */
		system("reboot");
	}

	event_add(arbiter->ev_send, &tv);
}

void _init_arbiter(struct arbiter_control *arbiter, const char *in_ip_str, const char *out_ip_str)
{
	int fd;
	int out_time = 1000;
	struct timeval tv;

	tv.tv_sec = 10;
	arbiter->dest[0].sin_family = AF_INET;
	arbiter->dest[0].sin_addr.s_addr = inet_addr(in_ip_str);
	arbiter->dest[1].sin_family = AF_INET;
	arbiter->dest[1].sin_addr.s_addr = inet_addr(out_ip_str);

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		printf("create socket fail.\n");
		return;
	}

	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&out_time, sizeof(int)); /* send timeout */
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&out_time, sizeof(int));  /* recv timeout */

	arbiter->sock = fd;

	arbiter->ev_send = evtimer_new(ha_basemgr->base, _icmp_send, arbiter);

	event_add(arbiter->ev_send, &tv);

}

void start_arbiter(const char *in_ip_str, const char *out_ip_str)
{
	return;
	/* if the PCIE channel is run as net interface */
	_init_arbiter(&_arbiter, in_ip_str, out_ip_str);
}