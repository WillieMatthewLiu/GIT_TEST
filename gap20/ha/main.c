#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

#include "config.h"
#include "thread.h"
#include "command.h"
#include "log.h"
#include "cmd_common.h"

#include "app_common.h"

#include "ha.h"
#include "ha_init.h"
#include "db_mysql.h"

int g_nBoardType = BOARDTYPE_IN;

static int g_nVtyPort = 2602;
static char* g_pVtyAddress = "127.0.0.1";

/* Process ID saved for use by init system */
const char* g_pIDFile = PATH_HA_PID;

/* Master of threads. */
struct thread_master* master;

/* Configuration file and directory. */
#define HA_DEFAULT_CONFIG "ha.conf.priv"
char* g_pConfigFile = SYSCONFDIR "ha.conf";
char  g_chConfigDefault[] = SYSCONFDIR HA_DEFAULT_CONFIG;

static void usage()
{
	printf("ha -Dd:f:o:i:\n");
	printf("option:\n");
	printf("\tD run as daemon.\n");
	printf("\tf config file\n");
	printf("\ti <ipaddr> In side board ip\n");
	printf("\to <ipaddr> Out side board ip\n");
}

int main(int argc, char *argv[])
{	
	/* preserve my name */
	char* p = NULL;	
	char* progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	/* Prepare master thread. */
	master = thread_master_create();

	zlog_default = openzlog(progname, ZLOG_HA,
		LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
	SCLogBufferInit(zlog_default);
	
	int ch = 0;
	int nDaemonMode = 0;
	uint16_t nPort = 8880;
	
	char* pInSideIP = NULL;
	char* pOutSideIP = NULL;
		
	while ((ch = getopt(argc, argv, "Ddf:a:o:i:p:")) != -1)
	{
		switch (ch)
		{
		case 'D':
		case 'd':
			nDaemonMode = 1;
			break;

		case 'f':
			g_pConfigFile = optarg;
			break;

		case 'o':
			pOutSideIP = SCStrdup(optarg);
			printf("out_side_ip: %s\n", pOutSideIP);
			break;

		case 'i':
			pInSideIP = SCStrdup(optarg);
			printf("in_side_ip: %s\n", pInSideIP);
			break;

		case 'p':
			nPort = atoi(optarg);
			printf("port: %s\n", optarg);
			break;

		default:
			usage();
			exit(0);
		}
	}

	signal_init(master, 0, NULL);

	if (nDaemonMode == 1)
	{
		daemon(0, 0);
	}
	else
	{
		zlog_set_level(zlog_default, ZLOG_DEST_STDOUT, LOG_DEBUG);
	}

	HA_LOG_DEBUG("Ha run!\n");

	/* Output pid of HA. */
	pid_output(g_pIDFile);

	g_nBoardType = cmd_get_boardtype();

	cmd_init(1);
	vty_init(master);
	memory_init();
	ipm_if_init();
	ipm_zebra_init(master);
	ha_cmd_init();
	
	/* Get configuration file. */
	vty_read_config(g_pConfigFile, g_chConfigDefault);

	// init configuration
	HaSysConfigInit();

	/* iptables set ha interface accept */
	HaIptInit();

	/* Create VTY's socket */
	vty_serv_sock(g_pVtyAddress, g_nVtyPort, HA_VTYSH_PATH);

	/* wait all application register finish */
	if (HaInit() != HA_SUCCESS)
	{
		HA_LOG_ERROR("ha init fail.\n");
		return -1;
	}

	/* start Ha */
	StartHa();

	if (g_nBoardType == BOARDTYPE_IN)
	{
		partner_init_in(pInSideIP ? pInSideIP : "192.168.0.2",
			pOutSideIP ? pOutSideIP : "192.168.0.3", nPort);
	}
	else if (g_nBoardType == BOARDTYPE_OUT)
	{
		partner_init_out(pOutSideIP ? pOutSideIP : "192.168.0.3", nPort);
	}

	if (pInSideIP)
	{
		SCFree(pInSideIP);
	}
	if (pOutSideIP)
	{
		SCFree(pOutSideIP);
	}

	/* enable db to recode operations */
	db_mysql_init(NULL);

	/* Execute each thread. */
	struct thread thread;
	while (thread_fetch(master, &thread))
	{
		thread_call(&thread);
	}

	return 0;
}