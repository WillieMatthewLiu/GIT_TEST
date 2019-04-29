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
#include "app_common.h"
#include "up_defs.h"
#include "ha.h"
#include "db_mysql.h"

/* Master of threads. */
struct thread_master *master;

static char *vty_addr = "127.0.0.1";

static int vty_port = 2603;

/* Process ID saved for use by init system */
const char *pid_file = PATH_UPGRADE_PID;

/* Configuration file and directory. */
#define HA_DEFAULT_CONFIG "gu.conf"
char *config_default_dir = NULL;
char *config_file = SYSCONFDIR HA_DEFAULT_CONFIG;

#define HA_LOG_FILE "ha.log"
char log_file[] = HA_LOG_FILE;


int boardtype = BOARDTYPE_IN;
int current_ha_state = HA_STATE_OOS;

static void usage()
{
    printf("ha -Da:o:i:\n");
    printf("option:\n");
    printf("\tD run as daemon.\n");
    printf("\ta <ipaddr> Arbiter ip\n");
    printf("\ti <ipaddr> In side board ip\n");
    printf("\to <ipaddr> Out side board ip\n");
}

int _get_boardtype()
{
    FILE *f;
    int type;
    char buf[128]={};
    if(access("/sys/class/gpio/gpio3/value", R_OK) <0)
        return type = -1;
    f = fopen("/sys/class/gpio/gpio3/value", "r");
    if(f == NULL)
        return type=-1;
    fgets(buf, 128, f);
    fclose(f);
    if(strncmp(buf, "1", 1)==0)
        return type = BOARDTYPE_ARBITER;
    else 
    {
        if(access("/sys/class/acorn/cpld/inout", R_OK) <0)
            return type=-1;
        f = fopen("/sys/class/acorn/cpld/inout", "r");
        if(f == NULL)
            return type=-1;
        fgets(buf, 128, f);
        fclose(f);

        if(strncmp(buf, "1", 1)==0)
            return type=BOARDTYPE_OUT;
        else
            return type=BOARDTYPE_IN;
    }
    return type;
}

int gu_ha_event_cb(HAEvent event, void *param){
    switch(event)
    {
        case HA_EVENT_GO_ACT:
            current_ha_state = HA_STATE_ACT;
            break;
        case HA_EVENT_GO_STB:
            current_ha_state = HA_STATE_STB;
            break;
        case HA_EVENT_GO_OOS:
        case HA_EVENT_GO_OOS_FORCED:
        case HA_EVENT_GO_OOS_NORMAL:
            current_ha_state = HA_STATE_OOS;
            break;
        default:
            break;
    }
    return 0;
}

void gu_ha_sync_recv_cb(uint32_t app_mod_id, const char *pData, uint32_t len)
{
    SCLogInfo("recv cmd: %s\n", pData);
    cmd_system_novty(pData);
}

int main(int argc, char *argv[])
{
    int ret;
    int ch=0;
    struct thread thread;
    int daemon_mode = 0;
    int test = 0;
    char *arbiter_ip = NULL, *in_side_ip = NULL, *out_side_ip = NULL;
    uint16_t port = UPGRADE_PORT;
    int register_retry = 0;

    /* Prepare master thread. */
    master = thread_master_create ();

    signal_init(master, 0, NULL);
   
    while((ch = getopt(argc, argv, "Da:o:i:p:t"))!= -1)
    {
        switch(ch)
        {
            case 'D':
                daemon_mode = 1;
                break;
            case 'a':
                arbiter_ip = SCStrdup(optarg);
                break;
            case 'o':
                out_side_ip = SCStrdup(optarg);
                printf("out_side_ip: %s\n", out_side_ip);
                break;
            case 'i':
                in_side_ip= SCStrdup(optarg);
                printf("in_side_ip: %s\n", in_side_ip);
                break;
            case 'p':
                port = atoi(optarg);
                printf("port: %s\n", optarg);
                break;
            case 't':
                test = 1;
                break;
            default:
                usage();
                exit(0);
        }
    }

    if(test)
    {
        if(boardtype == BOARDTYPE_IN){
            int fd = up_connect(NULL, arbiter_ip?arbiter_ip:"192.168.0.1", port);
            if(fd > 0)
                send(fd, "this is test", 12, 0);
            else
                printf("cannot connect to arbiter\n");
            close(fd);
        }
        exit(0);
    }

    if (daemon_mode)
        daemon(0, 0);

    pid_output(pid_file);
#ifdef USER_MEM_ALLOC
        ThreadMemInit("Main", pthread_self());
#endif

    boardtype = _get_boardtype();


    SCLogLoadConfig(daemon, log_file);

    if(RUN_AS_INNER())
    {
        while(have_ha())
        {
            ret = ha_app_register( UPGRADE_MOD_ID, 0,gu_ha_event_cb, gu_ha_sync_recv_cb, NULL);
            if (HA_SUCCESS == ret || HA_ERROR_EXIST == ret)
                break;
            register_retry++;
            if(register_retry >= 3)
            {
                SCLogInfo("Call ha_app_register failed.\n");
                return -1;
            }
            SCLogInfo("Call ha_app_register %d times.\n", register_retry);
            usleep(50*1000); //50ms
        }
        SCLogInfo("Call ha_app_register ok[%d].\n", ret);
    }

    cmd_init (1);
    vty_init (master);
    memory_init ();
    gu_cmd_init();
    usermgmt_init();


    /* Get configuration file. */
    if(!have_ha())
      vty_read_config (config_file, NULL);
    
    /* Create VTY's socket */
    vty_serv_sock (vty_addr, vty_port, GU_VTYSH_PATH);

    /*  */
    if(boardtype == BOARDTYPE_ARBITER)
        upgrade_init(boardtype, NULL, arbiter_ip?arbiter_ip:"192.168.0.1", port);
    else if(boardtype == BOARDTYPE_IN)
    {
       upgrade_init(boardtype, NULL, in_side_ip?in_side_ip:"192.168.0.2", port);;
    }
    else if(boardtype == BOARDTYPE_OUT)
    {
        upgrade_init(boardtype, NULL, out_side_ip?out_side_ip:"192.168.0.3", port);;
    }
    else
        ;//exit(0);

    if(in_side_ip)
        SCFree(in_side_ip);

    if(out_side_ip)
        SCFree(out_side_ip);

    /* enable db to recode operations */
    db_mysql_init(NULL);
    
    /* Execute each thread. */
    while (thread_fetch (master, &thread))
        thread_call (&thread);
    
    return 0;

}

