#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#define __USE_GNU
#endif
#include <zebra.h>

#include "command.h"
#include "if.h"
//#include "vtysh_config.h"
#include "memory.h"
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include "swe_ver.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "util-mem.h"

/* Show version. */
DEFUN(show_version,
	show_version_cmd,
	"show version",
	SHOW_STR
	"Displays the version information\n")
{
	char info[1024];

	if (RUN_AS_INNER() && strstr(self->string, "outer"))
	{
		return vty_adapter_run(vty, vty->usr_data);
	}

	FILE *fp;
	if (access("/COPYRIGHT", R_OK) == 0)
	{
		system("cat /COPYRIGHT");
	}
	else
	{
		FILE *fsn;
		char line[128] = { 0 };
		int flag = 0;
		vty_out(vty, "Company : %s%s", "RONGAN NETWORKS Co., Ltd.", VTY_NEWLINE);
		
		if (cmd_system_getout("/usr/bin/rongan_eeprom read serialnum | awk  \'{print $3}\'", line, 128))
		{
			if (strstr(line, "RSG020C6") != NULL)
			{
				vty_out(vty, "Product : RSG-U1200%s", VTY_NEWLINE);				
			}
			else if (strstr(line, "RSG030C6") != NULL)
			{
				vty_out(vty, "Product : RSG-U2000%s", VTY_NEWLINE);				
			}
			else if (strstr(line, "RSG060C6") != NULL)
			{
				vty_out(vty, "Product : RSG-U6000%s", VTY_NEWLINE);
			}
			else
			{				
				vty_out(vty, "Product : RSG-U1000%s", VTY_NEWLINE);
			}
			
			vty_out(vty, "Version : %s-%s.%s.%s-%s-%s%s%s-C%s.%s%s",
				SWE_APP,
				SWE_VER_V,
				SWE_VER_R,
				SWE_VER_C,
				SWE_VER_RD,
				SWE_VER_YEAR,
				SWE_VER_WEEK,
				SWE_VER_BUILD,
				SWE_VER_CUSTOM,
				SWE_VER_GIT_HEAD,
				VTY_NEWLINE);
			vty_out(vty, "Box S/N : ");
			vty_out(vty, "%s%s", line, VTY_NEWLINE);			
		}
		else
		{
			vty_out(vty, "Product : %s%s", SWE_PRODUCT, VTY_NEWLINE);
			vty_out(vty, "Version : %s-%s.%s.%s-%s-%s%s%s-C%s.%s%s",
				SWE_APP,
				SWE_VER_V,
				SWE_VER_R,
				SWE_VER_C,
				SWE_VER_RD,
				SWE_VER_YEAR,
				SWE_VER_WEEK,
				SWE_VER_BUILD,
				SWE_VER_CUSTOM,
				SWE_VER_GIT_HEAD,
				VTY_NEWLINE);
			vty_out(vty, "Box S/N : ");
			vty_out(vty, "%s%s", "", VTY_NEWLINE);
		}			
	}

	fp = fopen("/BUILD", "r");
	if (fp)
	{
		fgets(info, sizeof(info), fp);
		fclose(fp);
	}
	else
	{
		sprintf(info, "  Build : %s %s", __DATE__, __TIME__);
	}
	vty_out(vty, "%s%s", info, VTY_NEWLINE);
	return CMD_SUCCESS;
}

ALIAS(show_version,
	show_version_outer_cmd,
	"show outer version",
	SHOW_STR
	"outer\n"
	"Displays the version information\n")

	/* 显示CPU详细信息. nielin add 2013-10-22 */
	DEFUN(show_cpuinfo,
		show_cpuinfo_cmd,
		"show cpuinfo",
		SHOW_STR
		"Displays the cpu information\n")
{
	char info[4096];

	FILE *fp;
	fp = fopen("/proc/cpuinfo", "r");
	if (fp)
	{
		fread(info, sizeof(char), sizeof(info), fp);
		fclose(fp);
		vty_out(vty, "%s\n", info);
	}
	return CMD_SUCCESS;
}


DEFUN(show_meminfo,
	show_meminfo_cmd,
	"show meminfo",
	SHOW_STR
	"Displays the memory information\n")
{
	char info[4096];

	FILE *fp;
	fp = fopen("/proc/meminfo", "r");
	if (fp)
	{
		fread(info, sizeof(char), sizeof(info), fp);
		fclose(fp);
		vty_out(vty, "%s\n", info);
	}
	return CMD_SUCCESS;
}


DEFUN(show_interruptsinfo,
	show_interruptsinfo_cmd,
	"show interruptsinfo",
	SHOW_STR
	"Displays the interrupts information\n")
{
	char info[4096];

	FILE *fp;
	fp = fopen("/proc/interrupts", "r");
	if (fp)
	{
		fread(info, sizeof(char), sizeof(info), fp);
		fclose(fp);
		vty_out(vty, "%s\n", info);
	}
	return CMD_SUCCESS;
}


static int vty_set_login_info(struct vty *vty, const char *name, const char *access, const char *ip, int port)
{
	if (vty->username)
	{
		XFREE(MTYPE_VTY, vty->username);
	}
	vty->username = XSTRDUP(MTYPE_VTY, name);

	if (vty->access)
	{
		XFREE(MTYPE_VTY, vty->access);
	}
	vty->access = XSTRDUP(MTYPE_VTY, access);

	if (ip)
	{
		if (vty->login_ipaddr)
			XFREE(MTYPE_VTY, vty->login_ipaddr);
		vty->login_ipaddr = XSTRDUP(MTYPE_VTY, ip);
	}

	vty->login_port = port;
	return CMD_SUCCESS;
}

DEFUN_HIDDEN(set_login_info,
	set_login_info_cmd,
	"login name NAME access console",
	"Set login user infomations\n"
	"Login user name\n"
	"Login user name\n"
	"Login access\n"
	"Serial\n")
{
	return vty_set_login_info(vty, argv[0], "console", "ttyS0", 0);
}

DEFUN_HIDDEN(set_login_info2,
	set_login_info2_cmd,
	"login name NAME access (ssh|web) ip A.B.C.D port <0-65535>",
	"Set login user infomations\n"
	"Login user name\n"
	"Login user name\n"
	"Login access\n"
	"Serial\n"
	"SSH2\n"
	"Web\n"
	"Login IP address\n"
	"IP address\n"
	"Login port\n"
	"Port\n")
{
	return vty_set_login_info(vty, argv[0], argv[1], argv[2], atoi(argv[3]));
}

int cmd_common_init(int terminal)
{
	/* Each node's basic commands. */
	install_element(VIEW_NODE, &show_version_cmd);
	/*add 系统信息   nielin 2013-10-22 */
	install_element(VIEW_NODE, &show_cpuinfo_cmd);
	install_element(VIEW_NODE, &show_meminfo_cmd);
	install_element(VIEW_NODE, &show_interruptsinfo_cmd);
	if (terminal) {
		install_element(VIEW_NODE, &show_version_outer_cmd);
		install_element(VIEW_NODE, &set_login_info_cmd);
		install_element(VIEW_NODE, &set_login_info2_cmd);
	}

	install_element(ENABLE_NODE, &show_version_cmd);
	install_element(ENABLE_NODE, &show_cpuinfo_cmd);
	install_element(ENABLE_NODE, &show_meminfo_cmd);
	install_element(ENABLE_NODE, &show_interruptsinfo_cmd);
	if (terminal) {
		install_element(ENABLE_NODE, &show_version_outer_cmd);
		install_element(ENABLE_NODE, &set_login_info_cmd);
		install_element(ENABLE_NODE, &set_login_info2_cmd);
	}

	install_element(CONFIG_NODE, &show_version_cmd);

	return 0;
}

void cmd_install_node(struct cmd_node *node,
	int(*func) (struct vty *))
{
	install_node(node, func);
	install_default(node->node);
}

#ifdef LOG_SYSTEM_CMD
void write_debug(char* command)
{
	char buf[512];
	FILE *fp = NULL;
	fp = fopen(SYSTEM_DBG_FILE, "a+");
	if (fp == NULL)
	{
		return;
	}
	snprintf(buf, sizeof(buf), "User: %s SystemCmd: %s\n", "root"/*vtysh_getlogin()*/, command);
	buf[511] = '\0';

	fputs(buf, fp);
	fclose(fp);
}
#endif

/* Execute command in child process. */
int cmd_execute_system_command(char *command, int argc, char **argv)
{
	int ret;
	pid_t pid;
	int status;

	/* Call fork(). */
	pid = fork();

	if (pid < 0)
	{
		/* Failure of fork(). */
		fprintf(stderr, "Can't fork: %s\n", strerror(errno));
		return -1;
	}
	else if (pid == 0)
	{
		setuid(0);
		/* This is child process. we should use the execvp ?*/
		switch (argc)
		{
		case 0:
			ret = execlp(command, command, NULL);
			break;
		case 1:
			ret = execlp(command, command, argv[0], NULL);
			break;
		case 2:
			ret = execlp(command, command, argv[0], argv[1], NULL);
			break;
		case 3:
			ret = execlp(command, command, argv[0], argv[1], argv[2], NULL);
			break;
		case 4:
			ret = execlp(command, command, argv[0], argv[1], argv[2], argv[3], NULL);
			break;
		case 5:
			ret = execlp(command, command, argv[0], argv[1], argv[2], argv[3], argv[4], NULL);
			break;
		case 6:
			ret = execlp(command, command, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], NULL);
			break;
		case 7:
			ret = execlp(command, command, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], NULL);
			break;
		case 8:
			ret = execlp(command, command, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], NULL);
			break;
		}

		/* When execlp suceed, this part is not executed. */
		fprintf(stderr, "Can't execute %s: %s\n", command, strerror(errno));
		exit(1);
	}
	else
	{
		/* This is parent. */
		ret = wait4(pid, &status, 0, NULL);
	}
	return ret;
}

int cmd_system_real(struct vty *vty, char *cmd)
{
	pid_t pid;
	int status = 0;

	/* Call fork(). */
	pid = fork();

	if (pid < 0)
	{
#ifndef ERR_NO_PRINT
		/* Failure of fork(). */
		if (vty)
			vty_out(vty, "Can't fork: %s\n", strerror(errno));
#endif
		return -1;
	}
	else if (pid == 0)
	{
		setuid(0);
#ifdef LOG_SYSTEM_CMD
		write_debug(cmd);
#endif
		int status = system(cmd);
		if (-1 == status) {
#ifndef ERR_NO_PRINT
			if (vty)
				vty_out(vty, "Execute %s error!", cmd);
#endif
			exit(-1);
		}
		else {
			if (WIFEXITED(status)) {
				if (0 == WEXITSTATUS(status)) {
					exit(0);
				}
				else {
					exit(WEXITSTATUS(status));
				}
			}
			else {
				exit(WEXITSTATUS(status));
			}
			exit(0);
		}
	}
	else
	{
		/* This is parent. */
		wait4(pid, &status, 0, NULL);
		if (WEXITSTATUS(status) != 0) {
#ifdef LOG_SYSTEM_CMD
			{
				char buf[512];
				snprintf(buf, sizeof(buf), "Execute %s error, exit code: %d\n", cmd, WEXITSTATUS(status));
				write_debug(buf);
			}
#endif
#ifndef ERR_NO_PRINT
			if (vty) {
				vty_out(vty, "Execute %s error, exit code: %d\n", cmd, WEXITSTATUS(status));
			}
#endif
		}
#if 0
		VTY_LOG(VTY_LOG_ALERT, "Execute %s, exit code: %d\n", cmd, WEXITSTATUS(status));
#endif
	}
	return WEXITSTATUS(status);
}

int cmd_system_arg_real(struct vty *vty, char* format, ...)
{
#define CMD_BUFLEN   2048
	char buf[CMD_BUFLEN];
	va_list ap;
	int len = 0;

	va_start(ap, format);
	len += vsnprintf(buf + len, CMD_BUFLEN - len, format, ap);
	buf[CMD_BUFLEN - 1] = '\0';
	va_end(ap);
	return cmd_system_real(vty, buf);
}

int execl_safe(const char *path, const char *arg, ...)
{
	int n;
	char **argv;
	char **p;
	va_list args;
	char *newenviron[] = { NULL };

	n = 0;
	va_start(args, arg);
	do {
		++n;
	} while (va_arg(args, char *));
	va_end(args);

	p = argv = (char **)alloca((n + 1) * sizeof(char *));

	p[0] = (char *)arg;

	va_start(args, arg);
	do {
		*++p = va_arg(args, char *);
	} while (--n);
	va_end(args);

	n = execve(path, (char *const *)argv, newenviron);

	return n;
}

int cmd_system_getout(char* cmdstring, char* buf, int len)
{
	int   fd[2];
	pid_t pid;
	int   n, count = 0;
	if (pipe(fd) < 0)
		return -1;
	if ((pid = fork()) < 0)
		return -1;
	else if (pid > 0)     /* parent process */
	{
		char *enter_pos = NULL;
		close(fd[1]);     /* close write end */
		count = 0;
		while (count < len && (n = read(fd[0], buf + count, len - count)) > 0)
			count += n;
		close(fd[0]);
		if (waitpid(pid, NULL, 0) < 0)
			return -1;
	}
	else                  /* child process */
	{
		setuid(0);
		close(fd[0]);     /* close read end */
		if (fd[1] != STDOUT_FILENO)
		{
			if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO)
			{
				exit(-1);
			}
			close(fd[1]);
		}
		if (execl_safe("/bin/sh", "sh", "-c", cmdstring, (char*)0) == -1)
		{
			exit(-1);
		}
		exit(0);
	}
	return count;
}

/**
 * C++ version 0.4 char* style "itoa":
 * Written by Lukás Chmela
 * Released under GPLv3.
 */

char* itoa(int value, char* result, int base) {
	// check that the base if valid
	if (base < 2 || base > 36) {
		*result = '\0'; return result;
	}
	char* ptr = result, *ptr1 = result, tmp_char;
	int tmp_value;

	do {
		tmp_value = value;
		value /= base;
		*ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"
			[35 + (tmp_value - value * base)];

	} while (value);

	// Apply negative sign
	if (tmp_value < 0)
		*ptr++ = '-';
	*ptr-- = '\0';

	while (ptr1 < ptr) {
		tmp_char = *ptr;
		*ptr-- = *ptr1;
		*ptr1++ = tmp_char;
	}

	return result;
}

int vty_lock(const char *path)
{
#define PIDFILE_MASK 0644
	int tmp;
	int fd;
	pid_t pid;
	char buf[16];
	struct flock lock;
	mode_t oldumask;

	pid = getpid();

	oldumask = umask(0777 & ~PIDFILE_MASK);
	fd = open(path, O_RDWR | O_CREAT, PIDFILE_MASK);
	if (fd < 0)
	{
		return -1;
	}
	else
	{
		size_t pidsize;

		umask(oldumask);
		memset(&lock, 0, sizeof(lock));

		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;

		if (fcntl(fd, F_SETLK, &lock) < 0)
		{
			return -1;
		}

		sprintf(buf, "%d\n", (int)pid);
		pidsize = strlen(buf);
		if ((tmp = write(fd, buf, pidsize)) != (int)pidsize)
			zlog_err("Could not write pid %d to pid_file %s, rc was %d: %s",
			(int)pid, path, tmp, safe_strerror(errno));
		else if (ftruncate(fd, pidsize) < 0)
			zlog_err("Could not truncate pid_file %s to %u bytes: %s",
				path, (u_int)pidsize, safe_strerror(errno));
	}
	return 0;
}

int vty_unlock(const char *path)
{
#define PIDFILE_MASK 0644
	int tmp;
	int fd;
	pid_t pid;
	char buf[16];
	struct flock lock;
	mode_t oldumask;

	pid = getpid();

	oldumask = umask(0777 & ~PIDFILE_MASK);
	fd = open(path, O_RDWR | O_CREAT, PIDFILE_MASK);
	if (fd < 0)
	{
		return -1;
	}
	else
	{
		size_t pidsize;

		umask(oldumask);
		memset(&lock, 0, sizeof(lock));

		lock.l_type = F_UNLCK;
		lock.l_whence = SEEK_SET;

		if (fcntl(fd, F_SETLK, &lock) < 0)
		{
			return -1;
		}
	}
	return 0;
}


char* vty_setlogin_name(struct vty *vty, char* username)
{
	if (vty->username == NULL && username != NULL) {
		vty->username = strdup(username);
		if (vty->username == NULL) {
			return NULL;
		}
	}
	return vty->username;
}

char *vty_getlogin(struct vty *vty)
{
	return vty->username;
}

int get_ssh_login_ip(char* buffer, int len)
{
	char* ssh_ip = getenv("SSH_CLIENT");
	if (ssh_ip != NULL) {
		while (*ssh_ip && !isspace(*ssh_ip) && len > 1) {
			*buffer = *ssh_ip;
			buffer++;
			ssh_ip++;
			len--;
		}
		*buffer = '\0';
	}
	else {
		snprintf(buffer, len, "CONSOLE");
		buffer[len - 1] = '\0';
	}
	return 0;
}

int get_result_by_system(char* result, int result_len, const char *format, ...)
{
	va_list args;
	int len = 0;
	char buf[512];

	if (result == NULL)
		return -1;

	va_start(args, format);
	len = vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);
	if (len < 0 || len >= (int)sizeof(buf))
		return -1;
	return cmd_system_getout(buf, result, result_len);
}

struct vty_adapter * vty_adapter_init(struct vty_adapter *adpt, char* ip, uint16_t port)
{
	int sock;
	int ret;
	struct sockaddr_in serv;

	/* We should think about IPv6 connection. */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return NULL;

	/* Make server socket. */
	memset(&serv, 0, sizeof(struct sockaddr_in));
	serv.sin_family = AF_INET;
	serv.sin_port = htons(port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	serv.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
	if (!inet_aton(ip, &serv.sin_addr)) {
		return NULL;
	}

	/* Connect to zebra. */
	ret = connect(sock, (struct sockaddr *) &serv, sizeof(serv));
	if (ret < 0)
	{
		close(sock);
		return NULL;
	}


	if (!adpt) {
		adpt = XMALLOC(MTYPE_VTY, sizeof(struct vty_adapter) + VTY_ADPT_BUF_LEN);
		adpt->ip = XSTRDUP(MTYPE_VTY, ip);
	}
	adpt->port = port;
	adpt->fd = sock;
	adpt->timer_val.tv_sec = 60;
	adpt->buf = adpt->data;
	adpt->next = NULL;
	usleep(100);
	read(sock, adpt->buf, VTY_ADPT_BUF_LEN);
	set_nonblocking(sock);
	return adpt;
}


void vty_adapter_deinit(struct vty_adapter *adpt)
{
	if (!adpt)
		return;

	if (adpt->fd > 0)
		close(adpt->fd);
	XFREE(MTYPE_VTY, adpt);
}

#define VTY_ADPT_READ(num, adpt, hostname)\
do{\
    int rlen = 0;\
    num = 0;\
	FD_SET(adpt->fd, &readfd);\
    int ret = select (FD_SETSIZE, &readfd, NULL, NULL, &adpt->timer_val);\
    if (ret < 0)\
    {\
        return -1;\
    }\
    rlen = read(adpt->fd, &adpt->data[num], VTY_ADPT_BUF_LEN-1);\
    if(rlen >0) num += rlen; \
    }while(0)

int vty_adapter_run(struct vty *vty, struct vty_adapter* adpt)
{
	int num;
	fd_set readfd = {};
	//char buf[1024];
	struct utsname names;
	char *hostname = host.name;
	if (!hostname)
	{
		uname(&names);
		hostname = names.nodename;
	}

	if (NULL == adpt)
	{
		vty_out(vty, "don't connect to server.%s", VTY_NEWLINE);
		return -1;
	}
	char * buf = SCMalloc(strlen(vty->buf) + 3);
SEND:
	num = snprintf(buf, strlen(vty->buf) + 2, "%s\n", vty->buf);
	if (write(adpt->fd, buf, num) < 0)
	{
		vty_adapter_init(adpt, adpt->ip, adpt->port);
		if (CONFIG_NODE <= vty->node)
		{
			write(adpt->fd, "configure terminal\n", strlen("configure terminal\n"));
			read(adpt->fd, adpt->buf, VTY_ADPT_BUF_LEN);
		}
		goto SEND;
	}
	SCFree(buf);

	VTY_ADPT_READ(num, adpt, hostname);

	char *cp = strstr(adpt->data, "\r\n");
	if (cp)
		cp += 2;
	else
		cp = adpt->data;
	adpt->buf = cp;
	char *token = strstr(cp, hostname);
	if (token)
		*token = '\0';

	if (cp[0] > '\0') {
		vty_out(vty, "%s", cp);
	}

	return 0;
}

/* sort by alphabet */
static const char *sync_send_outer_cmd[] = {
	"configure",
	"enable",
	"end",
	"exit",
	"interface",
	"reset",
	"quit",
	"write",
	NULL
};

static int cmp_cmd(const char *cp) {
	const char **p = sync_send_outer_cmd;

	while (*p)
	{
		if (strncmp(cp, *p, strlen(*p)) == 0)
			return 1;
		(*p)++;
	}

	return 0;
}

/* if run as inner, some command will send to outer */
int vty_chain_base_cb(struct vty *vty, int ret)
{
	char *cp;
	struct vty_adapter *adpt;
	if (ret != CMD_SUCCESS)
		return CMD_SUCCESS;

	adpt = vty->usr_data;
	if (!adpt)
		return CMD_SUCCESS;

	cp = vty->buf;
	while (isspace(*cp))
		cp++;

	if (!cp || *cp == '\0')
		return CMD_SUCCESS;

	if (strncmp(cp, "show", 4) == 0)
		return CMD_SUCCESS;

	if (cmp_cmd(cp))
		return vty_adapter_run(vty, adpt);

	return CMD_SUCCESS;
}

struct vty_chain _vty_base_chain = {
	.func = vty_chain_base_cb
};

int board_type = BOARDTYPE_IN;
int cmd_get_boardtype()
{
#define BOARDTYPE_FILE "/var/run/boardtype"
	FILE *f;
	char data[64] = {};

	if (access(BOARDTYPE_FILE, R_OK) < 0)
	{
		fprintf(stderr, "boardtype file don't exist, check your system!!!");
		return -1;
	}

	f = fopen(BOARDTYPE_FILE, "r");
	if (NULL == f)
	{
		fprintf(stderr, "boardtype file can't read, check your system!!!");
		return -1;
	}

	fgets(data, 64, f);
	fclose(f);

	switch (data[0])
	{
	case 'a':
	case 'A':
		return board_type = BOARDTYPE_ARBITER;
	case 'i':
	case 'I':
		return board_type = BOARDTYPE_IN;
	case 'o':
	case 'O':
		return board_type = BOARDTYPE_OUT;
	default:
		return -1;
	}

	return -1;

}


