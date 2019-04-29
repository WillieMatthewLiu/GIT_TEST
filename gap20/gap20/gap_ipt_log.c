#include <sys/mman.h>
#include "thread.h"
#include "app_common.h"
//#include "command.h"
#include "db_mysql.h"

#define IPT_CMD_GET_QUEUE_SIZE ('I'<<24 | 'P'<<16 | 'T' <<8 | 'Q')
#define DEVICE_NAME "/dev/ipt_log_dev"

#define LOG_BUF_NUM (1024)

#define CPU_NUM (4)

#define INCREASE_INDEX(index)  do{ \
    index = ((index + 1) % LOG_BUF_NUM); \
}while(0)

#define S_SIZE (1024 - (sizeof(unsigned int) + 1))

struct sbuff {
	unsigned int    count;
	char        buf[S_SIZE + 1];
};
struct log_queue {
	int id;
	struct sbuff *buf_list;
};
static struct log_queue g_log_queue[CPU_NUM];
static int log_fd[4];

extern struct thread_master *master;

static void write_log(struct sbuff *sbuf)
{
	char *p = NULL;
	char *rule = NULL;
	char sip[32] = { 0 };
	char dip[32] = { 0 };
	char proto[32] = { 0 };
	char buf[1024] = { 0 };
	char sport[16] = { 0 };
	char dport[16] = { 0 };
	int proto_id = 0;
	uint32_t autoId[2] = { 0 };

	if (rule = strstr(sbuf->buf, "synflood")) {
		p = rule + strlen("synflood");
	}
	else if (rule = strstr(sbuf->buf, "udpflood")) {
		p = rule + strlen("udpflood");
	}
	else if (rule = strstr(sbuf->buf, "icmpflood")) {
		p = rule + strlen("icmpflood");
	}
	else if (rule = strstr(sbuf->buf, "land_attack")) {
		p = rule + strlen("land_attack");
	}
	else if (rule = strstr(sbuf->buf, "portscan fullxmas")) {
		p = rule + strlen("portscan fullxmas");
	}
	else if (rule = strstr(sbuf->buf, "portscan synrst")) {
		p = rule + strlen("portscan synrst");
	}
	else if (rule = strstr(sbuf->buf, "portscan")) {
		p = rule + strlen("portscan");
	}
	else {
		return;
	}

	*p++ = '\0';

	sscanf(p, "%s %s %s SRC=%s DST=%s %s %s %s %s %s PROTO=%s SPT=%s DPT=%s",
		buf, buf, buf, sip, dip, buf, buf, buf, buf, buf, proto, sport, dport);

	if (strcmp(proto, "tcp") == 0)
		proto_id = 6;
	else if (strcmp(proto, "udp") == 0)
		proto_id = 17;
	else if (strcmp(proto, "icmp") == 0)
		proto_id = 1;

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, proto_id, atoi(sport), atoi(dport), proto,
		"none", "none", l_warn, "", "检测到DDOS攻击", strlen(rule), rule);
}

static int thread_recv_log(struct thread *t)
{
	int i, ret, num;
	int fd = THREAD_FD(t);
	struct log_queue * log_queue = THREAD_ARG(t);

	num = read(fd, log_queue->buf_list, LOG_BUF_NUM * sizeof(struct sbuff));
	//SCLogInfo("cpuid: %d, num: %d\n", log_queue->id, num);
	for (i = 0; i < num; i++)
	{
		write_log(&log_queue->buf_list[i]);
	}
	thread_add_read(master, thread_recv_log, log_queue, fd);
	return 0;
}

int ipt_log_init()
{
	int i;
	char devname[32];
	pthread_t pthread;

	for (i = 0; i < CPU_NUM; i++)
	{
		snprintf(devname, 32, DEVICE_NAME"%d", i);
		log_fd[i] = open(devname, O_RDWR);
		if (log_fd[i] < 0)
		{
			SCLogInfo("open ipt_log_dev failed\n");
			continue;
		}

		g_log_queue[i].id = i;
		g_log_queue[i].buf_list = SCMalloc(LOG_BUF_NUM * sizeof(struct sbuff));
		if (!g_log_queue[i].buf_list)
			continue;

		thread_add_read(master, thread_recv_log, &g_log_queue[i], log_fd[i]);
	}

	return 0;
}

void ipt_log_exit()
{
	int i;

	for (i = 0; i < CPU_NUM; i++)
	{
		close(log_fd[i]);
		SCFree(g_log_queue[i].buf_list);
	}
}
