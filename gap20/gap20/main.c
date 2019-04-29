#include <sys/types.h>
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "lib/memory.h"
#include "prefix.h"
#include "log.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "vrf.h"

#include "app_common.h"
#include "main_fwddrv.h"
#include "main_inouter.h"
#include "main_pciproxy.h"
#include "gapconfig.h"
#include "oscall.h"
#include "gap_ipt_log.h"
#include "log.h"
#include "thread.h"
#include "cmd_common.h"
#include "led_ctl.h"

struct thread_master *master;

enum RUN_MODE
{
	RUN_INNER = BOARDTYPE_IN,
	RUN_OUTER = BOARDTYPE_OUT,
	RUN_ARBITER = BOARDTYPE_ARBITER,
	RUN_FWD,
	RUN_PROXY
};
enum RUN_MODE get_run_mode()
{
	return cmd_get_boardtype();
}

int usage()
{
	printf("gap20 command help\n");
	printf("[-Dd]: daemon run\n");
	printf("[-m]: [arbiter / outer / inner / proxy], set runmode\n");
	printf("[-a]: [ip], set arbiter ip\n");
	printf("[-p]: [port], set listen port\n");

	return 0;
}
/* SIGHUP handler. */
static void
sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload of config file. */
	;
}

/* SIGINT handler. */
static void
sigint(void)
{
	zlog_notice("Terminating on signal");

	exit(0);
}

/* SIGUSR1 handler. */
static void
sigusr1(void)
{
	zlog_rotate(NULL);
}

struct quagga_signal_t gap_signals[] =
{
  {
	.signal = SIGHUP,
	.handler = &sighup,
  },
  {
	.signal = SIGUSR1,
	.handler = &sigusr1,
  },
  {
	.signal = SIGINT,
	.handler = &sigint,
  },
  {
	.signal = SIGTERM,
	.handler = &sigint,
  },
};

int main(int argc, char **argv)
{
	char ch;
	int daemon_mode = 0;
	char *ip = NULL;
	char *port = NULL;
	char *progname, *p;
	char *pid_file = "/var/run/gap20.pid";

	int ret = -1;
	struct thread t;

	enum RUN_MODE mode = get_run_mode();
	/* preserve my name */
	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);
	zlog_default = openzlog(progname, ZLOG_GAP,
		LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);	

	while ((ch = getopt(argc, argv, "Ddm:a:p:")) != -1)
	{
		switch (ch)
		{
		case 'D':
		case 'd':
			daemon_mode = 1;
			break;

		case 'm':
			if (strcmp(optarg, "arbiter") == 0)
				mode = RUN_ARBITER;
			else if (strcmp(optarg, "outer") == 0)
				mode = RUN_OUTER;
			else if (strcmp(optarg, "inner") == 0)
				mode = RUN_INNER;
			else if (strcmp(optarg, "fwddrv") == 0)
				mode = RUN_FWD;
			else if (strcmp(optarg, "proxy") == 0)
				mode = RUN_PROXY;
			else
				return usage();
			break;

		case 'a':
			ip = optarg;
			break;

		case 'p':
			port = optarg;
			break;

		default:
			usage();
			return -1;
		}
	}

	OpenCoreDump();

	cmd_get_boardtype();

	if (daemon_mode == 1)
	{
		daemon(0, 0);
	}		
	else
	{
		zlog_set_level(zlog_default, ZLOG_DEST_STDOUT, LOG_DEBUG);		
	}

	SCLogInfo("gap20 run!");	

	/* Output pid of zebra. */
	pid_output(pid_file);
#ifdef USER_MEM_ALLOC
	ThreadMemInit("Main", pthread_self());
#endif

	led_ctrl(LED_GREEN);

	master = thread_master_create();

	signal_init(master, array_size(gap_signals), gap_signals);
	switch (mode)
	{
	case RUN_FWD:
		SCLogInfo("run fwddrv");
		ret = main_fwddrv();
		break;

	case RUN_PROXY:
		SCLogInfo("run proxy");
		ret = main_pciproxy(ip, port);
		break;

	default:
		ret = inner_outer_run();
		break;
	}

	gap_vty_init(cmd_get_boardtype());

	while (thread_fetch(master, &t))
	{
		thread_call(&t);
	}

	led_ctrl(LED_OFF);

	return ret;
}

/******************************************************
功能：  打开崩溃日志记录功能
参数：  无
返回值：无
******************************************************/
void OpenCoreDump()
{
	struct rlimit rlim;
	struct rlimit rlim_new;

	if (getrlimit(RLIMIT_CORE, &rlim) == 0)
	{
		rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &rlim_new) != 0)
		{
			rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
			(void)setrlimit(RLIMIT_CORE, &rlim_new);
		}
	}
}

