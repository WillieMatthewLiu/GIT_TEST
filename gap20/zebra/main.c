/* zebra daemon main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

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

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/irdp.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_fpm.h"
#include "db_mysql.h"
#include "zebra_ha.h"

 /* Zebra instance */
struct zebra_t zebrad =
{
  .rtm_table_default = 0,
};

/* process id. */
pid_t pid;

/* Pacify zclient.o in libzebra, which expects this variable. */
struct thread_master *master;

/* Route retain mode flag. */
int retain_mode = 0;

/* Don't delete kernel route. */
int keep_kernel_mode = 0;

#ifdef HAVE_NETLINK
/* Receive buffer size for netlink socket */
u_int32_t nl_rcvbufsize = 0;
#endif /* HAVE_NETLINK */

/* Command line options. */
struct option longopts[] =
{
  { "batch",       no_argument,       NULL, 'b'},
  { "daemon",      no_argument,       NULL, 'd'},
  { "keep_kernel", no_argument,       NULL, 'k'},
  { "fpm_format",  required_argument, NULL, 'F'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "socket",      required_argument, NULL, 'z'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "retain",      no_argument,       NULL, 'r'},
  { "dryrun",      no_argument,       NULL, 'C'},
#ifdef HAVE_NETLINK
  { "nl-bufsize",  required_argument, NULL, 's'},
#endif /* HAVE_NETLINK */
  { "user",        required_argument, NULL, 'u'},
  { "group",       required_argument, NULL, 'g'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

zebra_capabilities_t _caps_p[] =
{
  ZCAP_NET_ADMIN,
  ZCAP_SYS_ADMIN,
  ZCAP_NET_RAW,
};

/* zebra privileges to run with */
struct zebra_privs_t zserv_privs =
{
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
	.user = QUAGGA_USER,
	.group = QUAGGA_GROUP,
	#endif
	#ifdef VTY_GROUP
	  .vty_group = VTY_GROUP,
	  #endif
		.caps_p = _caps_p,
		.cap_num_p = 3,//array_size(_caps_p),
  .cap_num_i = 0
};

/* Default configuration file path. */
char *config_file = SYSCONFDIR "zebra.conf";
char *config_default_dir = SYSCONFDIR "zebra.conf.priv";

/* Process ID saved for use by init system */
const char *pid_file = PATH_ZEBRA_PID;

/* board type */
extern int board_type;


/* Help information display. */
static void
usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	else
	{
		printf("Usage : %s [OPTION...]\n\n"\
			"Daemon which manages kernel routing table management and "\
			"redistribution between different routing protocols.\n\n"\
			"-b, --batch        Runs in batch mode\n"\
			"-d, --daemon       Runs in daemon mode\n"\
			"-f, --config_file  Set configuration file name\n"\
			"-F, --fpm_format   Set fpm format to 'netlink' or 'protobuf'\n"\
			"-i, --pid_file     Set process identifier file name\n"\
			"-z, --socket       Set path of zebra socket\n"\
			"-k, --keep_kernel  Don't delete old routes which installed by "\
			"zebra.\n"\
			"-C, --dryrun       Check configuration for validity and exit\n"\
			"-A, --vty_addr     Set vty's bind address\n"\
			"-P, --vty_port     Set vty's port number\n"\
			"-r, --retain       When program terminates, retain added route "\
			"by zebra.\n"\
			"-u, --user         User to run as\n"\
			"-g, --group	  Group to run as\n", progname);
#ifdef HAVE_NETLINK
		printf("-s, --nl-bufsize   Set netlink receive buffer size\n");
#endif /* HAVE_NETLINK */
		printf("-v, --version      Print program version\n"\
			"-h, --help         Display this help and exit\n"\
			"\n"\
			"Report bugs to %s\n", ZEBRA_BUG_ADDRESS);
	}

	exit(status);
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

	if (!retain_mode)
		rib_close();
#ifdef HAVE_IRDP
	irdp_finish();
#endif

	exit(0);
}

/* SIGUSR1 handler. */
static void
sigusr1(void)
{
	zlog_rotate(NULL);
}

struct quagga_signal_t zebra_signals[] =
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

/* Callback upon creating a new VRF. */
static int
zebra_vrf_new(vrf_id_t vrf_id, void **info)
{
	struct zebra_vrf *zvrf = *info;

	if (!zvrf)
	{
		zvrf = zebra_vrf_alloc(vrf_id);
		*info = (void *)zvrf;
		router_id_init(zvrf);
	}

	return 0;
}

/* Callback upon enabling a VRF. */
static int
zebra_vrf_enable(vrf_id_t vrf_id, void **info)
{
	struct zebra_vrf *zvrf = (struct zebra_vrf *) (*info);

	assert(zvrf);

#if defined (HAVE_RTADV)
	rtadv_init(zvrf);
#endif
	kernel_init(zvrf);
	interface_list(zvrf);
	route_read(zvrf);

	return 0;
}

/* Callback upon disabling a VRF. */
static int
zebra_vrf_disable(vrf_id_t vrf_id, void **info)
{
	struct zebra_vrf *zvrf = (struct zebra_vrf *) (*info);
	struct listnode *list_node;
	struct interface *ifp;

	assert(zvrf);

	rib_close_table(zvrf->table[AFI_IP][SAFI_UNICAST]);
	rib_close_table(zvrf->table[AFI_IP6][SAFI_UNICAST]);

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(vrf_id), list_node, ifp))
	{
		int operative = if_is_operative(ifp);
		UNSET_FLAG(ifp->flags, IFF_UP);
		if (operative)
			if_down(ifp);
	}

#if defined (HAVE_RTADV)
	rtadv_terminate(zvrf);
#endif
	kernel_terminate(zvrf);

	list_delete_all_node(zvrf->rid_all_sorted_list);
	list_delete_all_node(zvrf->rid_lo_sorted_list);

	return 0;
}

/* Zebra VRF initialization. */
static void
zebra_vrf_init(void)
{
	vrf_add_hook(VRF_NEW_HOOK, zebra_vrf_new);
	vrf_add_hook(VRF_ENABLE_HOOK, zebra_vrf_enable);
	vrf_add_hook(VRF_DISABLE_HOOK, zebra_vrf_disable);
	vrf_init();
}

int zebra_vty_create(struct vty *vty)
{
	struct vty_adapter *adpts;

	adpts = vty_adapter_init(NULL, OUTER_DEFAULT_IP_STR, ZEBRA_VTY_PORT);
	vty->usr_data = adpts;

	return 0;
}


int zebra_vty_close(struct vty *vty)
{
	struct vty_adapter *adpt = vty->usr_data;

	if (adpt)
		vty_adapter_deinit(adpt);
	vty->usr_data = NULL;

	return 0;
}

int zebra_vty_chain_cb(struct vty *vty, int ret)
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

	if (strncmp(cp, "enable", strlen("enable")) == 0
		|| strncmp(cp, "configure", strlen("configure")) == 0
		|| strncmp(cp, "interface", strlen("interface")) == 0
		|| strncmp(cp, "end", strlen("end")) == 0
		|| strncmp(cp, "quit", strlen("quit")) == 0
		|| strncmp(cp, "exit", strlen("exit")) == 0
		|| strncmp(cp, "reset", strlen("reset")) == 0
		|| (strncmp(cp, "write", strlen("write")) == 0
			&& (strstr(cp, "file") || strstr(cp, "memory"))))
		return vty_adapter_run(vty, adpt);

	return CMD_SUCCESS;
}

struct vty_chain zebra_vty_chain = {
	.func = zebra_vty_chain_cb
};

/* Main startup routine. */
int
main(int argc, char **argv)
{
	char *p;
	char *vty_addr = "127.0.0.1";
	int vty_port = ZEBRA_VTY_PORT;
	int dryrun = 0;
	int batch_mode = 0;
	int daemon_mode = 0;
	char *progname;
	struct thread thread;
	char *zserv_path = NULL;
	char *fpm_format = NULL;

	/* Set umask before anything for security */
	umask(0027);

	/* preserve my name */
	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	zlog_default = openzlog(progname, ZLOG_ZEBRA,
		LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);

	while (1)
	{
		int opt;

#ifdef HAVE_NETLINK  
		opt = getopt_long(argc, argv, "bdkf:F:i:z:hA:P:ru:g:vs:C", longopts, 0);
#else
		opt = getopt_long(argc, argv, "bDdkf:F:i:z:hA:P:ru:g:vC", longopts, 0);
#endif /* HAVE_NETLINK */

		if (opt == EOF)
			break;

		switch (opt)
		{
		case 0:
			break;

		case 'b':
			batch_mode = 1;
					
		case 'D':
		case 'd':
			daemon_mode = 1;
			break;

		case 'k':
			keep_kernel_mode = 1;
			break;

		case 'C':
			dryrun = 1;
			break;

		case 'f':
			config_file = optarg;
			break;

		case 'F':
			fpm_format = optarg;
			break;

		case 'A':
			vty_addr = optarg;
			break;

		case 'i':
			pid_file = optarg;
			break;

		case 'z':
			zserv_path = optarg;
			break;

		case 'P':
			/* Deal with atoi() returning 0 on failure, and zebra not
			   listening on zebra port... */
			if (strcmp(optarg, "0") == 0)
			{
				vty_port = 0;
				break;
			}
			vty_port = atoi(optarg);
			if (vty_port <= 0 || vty_port > 0xffff)
				vty_port = ZEBRA_VTY_PORT;
			break;

		case 'r':
			retain_mode = 1;
			break;

#ifdef HAVE_NETLINK
		case 's':
			nl_rcvbufsize = atoi(optarg);
			break;
#endif /* HAVE_NETLINK */

		case 'u':
			zserv_privs.user = optarg;
			break;

		case 'g':
			zserv_privs.group = optarg;
			break;

		case 'v':
			print_version(progname);
			exit(0);
			break;

		case 'h':
			usage(progname, 0);
			break;

		default:
			usage(progname, 1);
			break;
		}
	}

	board_type = cmd_get_boardtype();
	/* Make master thread emulator. */
	zebrad.master = thread_master_create();
	master = zebrad.master;

	/* privs initialise */
	zprivs_init(&zserv_privs);

	/* Vty related initialize. */
	signal_init(zebrad.master, array_size(zebra_signals), zebra_signals);
	cmd_init(1);
	vty_init(zebrad.master);
	memory_init();

	/* Zebra related initialize. */
	zebra_init();
	rib_init();
	zebra_if_init();
	zebra_debug_init();
	router_id_cmd_init();
	zebra_vty_init();
	access_list_init();
	prefix_list_init();
#if defined (HAVE_RTADV)
	rtadv_cmd_init();
#endif
#ifdef HAVE_IRDP
	irdp_init();
#endif

	/* For debug purpose. */
	/* SET_FLAG (zebra_debug_event, ZEBRA_DEBUG_EVENT); */

	/* Initialize VRF module, and make kernel routing socket. */
	zebra_vrf_init();



#ifdef HAVE_SNMP
	zebra_snmp_init();
#endif /* HAVE_SNMP */

#ifdef HAVE_FPM
	zfpm_init(zebrad.master, 1, 0, fpm_format);
#else
	zfpm_init(zebrad.master, 0, 0, fpm_format);
#endif


	/* Process the configuration file. Among other configuration
	*  directives we can meet those installing static routes. Such
	*  requests will not be executed immediately, but queued in
	*  zebra->ribq structure until we enter the main execution loop.
	*  The notifications from kernel will show originating PID equal
	*  to that after daemon() completes (if ever called).
	*/
	if (!have_ha())
		vty_read_config(config_file, config_default_dir);

	/* Don't start execution if we are in dry-run mode */
	if (dryrun)
		return(0);

	/* Count up events for interfaces */
	if_startup_count_up();

	/* Clean up rib. */
	rib_weed_tables();

	/* Exit when zebra is working in batch mode. */
	if (batch_mode)
		exit(0);

	/* Daemonize. */
	if (daemon_mode && daemon(0, 0) < 0)
	{
		zlog_err("Zebra daemon failed: %s", strerror(errno));
		exit(1);
	}

	/* Output pid of zebra. */
	pid_output(pid_file);

	/* After we have successfully acquired the pidfile, we can be sure
	*  about being the only copy of zebra process, which is submitting
	*  changes to the FIB.
	*  Clean up zebra-originated routes. The requests will be sent to OS
	*  immediately, so originating PID in notifications from kernel
	*  will be equal to the current getpid(). To know about such routes,
	* we have to have route_read() called before.
	*/
	if (!keep_kernel_mode)
		rib_sweep_route();

	/* Needed for BSD routing socket. */
	pid = getpid();

	/* This must be done only after locking pidfile (bug #403). */
	zebra_zserv_socket_init(zserv_path);

	/* Make vty server socket. */
	if (BOARDTYPE_ARBITER == board_type)
	{
		vty_addr = ARBITER_DEFAULT_IP_STR;
	}
	else if (BOARDTYPE_OUT == board_type)
	{
		vty_addr = OUTER_DEFAULT_IP_STR;
		vty_serv_sock("127.0.0.1", vty_port, NULL);
	}
	else
	{
		vty_add_hook(VTY_CREATE_HOOK, zebra_vty_create);
		vty_add_hook(VTY_CLOSE_HOOK, zebra_vty_close);
		vty_chain_register(&zebra_vty_chain);

		haa_vty_add_hook();
	}
	vty_serv_sock(vty_addr, vty_port, ZEBRA_VTYSH_PATH);

	/* ha */
	if (have_ha())
		zebra_ha_init();
	/* Print banner. */
	zlog_notice("Zebra %s starting: vty@%d", QUAGGA_VERSION, vty_port);

	/* enable db to recode operations */
	db_mysql_init(NULL);

	while (thread_fetch(zebrad.master, &thread))
		thread_call(&thread);

	/* Not reached... */
	return 0;
}
