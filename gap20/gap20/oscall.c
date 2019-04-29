
#include "app_common.h"
#include "oscall.h"
#include "gapconfig.h"

int addnat(const char *sip, uint16_t sport, const char *dip, uint16_t dport, int protocol)
{
	char cmd[1024];
	if (protocol == 0)
		snprintf(cmd, sizeof(cmd), "iptables -t nat -A PREROUTING -p tcp -d %s --dport %d -j DNAT --to %s:%d", sip, sport, dip, dport);
	else if (protocol == 1)
		snprintf(cmd, sizeof(cmd), "iptables -t nat -A PREROUTING -p udp -d %s --dport %d -j DNAT --to %s:%d", sip, sport, dip, dport);
	int ret = os_exec(cmd);
	return ret;
}

int delnat(const char *sip, uint16_t sport, const char *dip, uint16_t dport)
{
	int ret;
	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "iptables -t nat -D PREROUTING -p tcp -d %s --dport %d -j DNAT --to %s:%d", sip, sport, dip, dport);
	ret = os_exec(cmd);
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "iptables -t nat -D PREROUTING -p udp -d %s --dport %d -j DNAT --to %s:%d", sip, sport, dip, dport);
	ret = os_exec(cmd);
	SCLogInfo(cmd);
	return ret;
}

int addr2str(u_int ip, char *ret)
{
	uint8_t *p = (uint8_t*)&ip;
	return sprintf(ret, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
}

void imac_addr(char *str, uint8_t *mac)
{
	char *p;
	mac[0] = (uint8_t)strtol(str + 0, &p, 16);
	mac[1] = (uint8_t)strtol(str + 3, &p, 16);
	mac[2] = (uint8_t)strtol(str + 6, &p, 16);
	mac[3] = (uint8_t)strtol(str + 9, &p, 16);
	mac[4] = (uint8_t)strtol(str + 12, &p, 16);
	mac[5] = (uint8_t)strtol(str + 15, &p, 16);
}

// 输入指定的key，返回对应的value，没有KEY则对应的value返回NULL
// char str[] = "smac=1;dmac=22;sip=3;dip=44;sport=5;dport=66;uid=7;uname=88", *dmac, *uname;
// parsestring(str, "dmac", &dmac, "uname", &uname, NULL);
int parsestring(char *str, ...)
{
	int cnt = 0;
	char *key[1000] = { 0 }, *value[1000];
	for (char *ctx, *iter = strtok_s(str, ";", &ctx); iter != NULL; iter = strtok_s(NULL, ";", &ctx))
	{
		char *v = strchr(iter, '=');
		if (v == NULL)
			continue;
		*v++ = '\0';
		key[cnt] = iter;
		value[cnt] = v;
		cnt++;

		if (cnt >= 1000)
			break;
	}

	va_list va;
	va_start(va, str);
	while (1)
	{
		char *s = va_arg(va, char*);
		char **p = va_arg(va, char**);
		if (s == NULL || p == NULL)
			break;
		*p = NULL;

		for (int i = 0; i < cnt; i++)
		{
			if (strcmp(s, key[i]) != 0)
				continue;
			*p = value[i];
			break;
		}
	}
	va_end(va);
	return 0;
}

int os_exec(const char *cmd)
{
	// 	typedef void (*sighandler_t)(int);
	// 	sighandler_t old_handler = signal(SIGCHLD, SIG_DFL);
	// 	int ret = system(cmd);
	// 	signal(SIGCHLD, old_handler);
	// 	return ret;

	FILE *f = popen(cmd, "r");
	if (f == NULL)
		return -1;

	char buff[1024];
	while (fread(buff, 1, sizeof(buff), f) > 0);

	int ret = pclose(f);
	if (WIFEXITED(ret) == 0)
		return -1;
	ret = WEXITSTATUS(ret);
	//printf("os_exec, ret: %d, cmd: %s", ret, cmd);
	return ret;
}

int os_exec_rd(const char *cmd, char **response)
{
	int len;
	char buff[1024];
	struct evbuffer *bf = evbuffer_new();
	if (bf == NULL)
		return -1;
	FILE *f = popen(cmd, "r");
	if (f == NULL)
	{
		evbuffer_free(bf);
		return -1;
	}
	while ((len = fread(buff, 1, sizeof(buff), f)) > 0)
		evbuffer_add(bf, buff, len);
	int ret = pclose(f);
	if (WIFEXITED(ret) == 0)
		return -1;
	ret = WEXITSTATUS(ret);
	len = (int)evbuffer_get_length(bf);
	char *result = SCMalloc(len + 1);
	if (result == NULL)
	{
		evbuffer_free(bf);
		return -1;
	}
	evbuffer_remove(bf, result, len);
	result[len] = '\0';
	*response = result;
	return ret;
}




void os_sleep(int msec)
{
	usleep(1000 * msec);
}

int os_gettick()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

uint64_t os_longlonginc(uint64_t *p, uint64_t n)
{
	return __sync_add_and_fetch(p, n);
}

uint64_t os_longlongdec(uint64_t *p, uint64_t n)
{
	return __sync_sub_and_fetch(p, n);
}

int getarp(char *ifname, char *ip, void *mac)
{
	int ret;
	static int sock_fd = 0;
	struct arpreq req;
	struct sockaddr_in *sin;
	struct interface *ifp;

	ifp = if_lookup_by_name(ifname);
	if (ifp == NULL)
		return -1;

	memset(&req, 0, sizeof(req));
	sin = (struct sockaddr_in *)&req.arp_pa;

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(ip);
	strncpy(req.arp_dev, ifp->name, sizeof(req.arp_dev));

	if (sock_fd == 0)
	{
		sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock_fd < 0)
			return -1;
	}

	ret = ioctl(sock_fd, SIOCGARP, &req);
	if (ret < 0)
		return -1;

	memcpy(mac, req.arp_ha.sa_data, 6);
	return 0;
}

int readeprom(char *key, char *ret, int len)
{
	return -1;
}
