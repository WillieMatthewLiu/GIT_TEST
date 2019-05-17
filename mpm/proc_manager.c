#ifdef __plusplus
extern "C"{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <getopt.h>

#include <errno.h>
#include <stropts.h>            /* for ioctl() */
#include <linux/watchdog.h>        /* for 'struct watchdog_info' */
#include <syslog.h>
#include <sched.h>


#include "proc_manager.h"
#include "pm_config.h"
#include "running_process.h"
#include "mpm_led.h"

static volatile int mpm_sigflag = 0;
static int g_wd_fd1 = -1;
//static int g_wd_fd2 = -1;
static pthread_t g_wd_fdthread;

static const int MAX_TIMEOUT = 254;    /* Reasonable limit? Not -1 as char, and probably long enough. */


#if 0
static void SignalHandlerMpmSigusr1 (int signo) {
    mpm_sigflag = 1;
}
#endif
    
int update_all_proc_stat(struct kp_mgmt* kpm);

void pm_usage(const char *proc_name)
{
    printf("NAME\n");
    printf("\t%s - Process Manager\n",proc_name);
    printf("SYNOPSIS\n");
    printf("\t%s [option] ...\n",proc_name);
    printf("DESCRIPTION\n");
    printf("\tProcess Manager, if a process in configuration file died, the Process Manager will restart it.\n");
    printf("\t-h\n");
    printf("\t\t%s help\n",proc_name);
    printf("\t-n num\n");
    printf("\t\tHow many Process Manager will start. if not set, default number is 2. The Value must large than 2\n");
    printf("\t-c filename\n");
    printf("\t\tConfiguration file, if not set, default file is /etc/mpm.conf\n");
    printf("\t-t\n");
    printf("\t\tShutdown ProcessManager self.\n");
}

static struct shm_area *getshmst()
{
    key_t key;
    int shmid;
    struct shm_area *sa;

    key = get_shm_key();

    if( -1 == ( shmid = shmget(key, sizeof(struct shm_area), IPC_CREAT | IPC_EXCL | 0666)))
    {
        if(errno != EEXIST)
            return NULL;  
        shmid = shmget(key, sizeof(struct shm_area), 0666);
        if(-1 == shmid)
            return NULL;
    }

    sa = (struct shm_area *)shmat(shmid, NULL, 0);
    if(sa == (void *)-1)
    {
        return NULL;
    }
    
    return sa;    
    
}

int search_and_restart2(struct kp_mgmt* kpm)
{
    int i;
    char cmdbuf[1024];
    int n=0;

    for(i=0; i<kpm->n; i++)
    {
        if(E_PROC_STAT_MIN == kpm->kpm[i].status ||
            E_PROC_STAT_Z == kpm->kpm[i].status ||
            E_PROC_STAT_MAX == kpm->kpm[i].status)
        {
            int len = 0;
            if(kpm->kpm[i].env)
                len += sprintf(cmdbuf+len, "%s ",kpm->kpm[i].env);
            
            len += sprintf(cmdbuf+len, "%s ",
                    kpm->kpm[i].process);
            if(kpm->kpm[i].param)
                len += sprintf(cmdbuf+len, "%s ",kpm->kpm[i].param);
            printf("==========>%s\n",cmdbuf);
            system(cmdbuf);
            //just stop feed watchdog
            
        }   
        kpm->kpm[i].status = E_PROC_STAT_MIN;
    }

    return 0;
    
}


void check_run_led(struct shm_area *sa)
{
    static int si_run_sw=0xff;
    int sw = 0;
    int sum;

    sum = sa->run_led1 + sa->run_led2;

    switch (sum) {
    case 0:
        sw = MPM_LED_OFF;
        break;
    case 1:
        sw = MPM_LED_RED_ON;
        break;
    case 2:
        sw = MPM_LED_GREEN_BLINK;
        break;
    default:
        sw = MPM_LED_OFF;
        break;
    }
    if (si_run_sw != sw) {
        si_run_sw = sw;
        mpm_set_run_led(si_run_sw);
    }
    
}

void check_alarm_led(struct shm_area *sa)
{
    static int si_alarm_sw=0xff;
    int sw = 0;
    int sum;

    sum = sa->alarm_led1 + sa->alarm_led2;

    if (sum >=MPM_LED_RED_ON  && sum <MPM_LED_RED_BLINK) {
        sw = MPM_LED_RED_ON;
    }else if (sum>=MPM_LED_RED_BLINK ) {
        sw = MPM_LED_RED_BLINK;
    }else{
        sw = MPM_LED_OFF;
    }
    if (si_alarm_sw != sw) {
        si_alarm_sw = sw;
        mpm_set_alarm_led(si_alarm_sw);
    }
}


#if defined(MIPS_PLATFORM)|| defined(X86_PLATFORM)
/*
 * Once opened, call this to query or change the watchdog timer value.
 */

static int set_watchdog_timeout(int timeout)
{
    int rv = -1;

    if (g_wd_fd1 != -1) {
        if (timeout > 0) {
            if (timeout > MAX_TIMEOUT)
                timeout = MAX_TIMEOUT;

            /* Set the watchdog hard-stop timeout; default = unset (use driver default) */
            if (ioctl(g_wd_fd1, WDIOC_SETTIMEOUT, &timeout) < 0) {
                syslog(LOG_INFO, "cannot set timeout %d (errno = %d = '%s')\n", timeout, errno, strerror(errno));
            } else {
                syslog(LOG_INFO, "watchdog now set to %d seconds\n", timeout);
                rv = 0;
            }
        }
    }

    return rv;
}

/*
 * Close the watchdog device, this normally stops the hardware timer to prevent a
 * spontaneous reboot, but not if the kernel is compiled with the
 * CONFIG_WATCHDOG_NOWAYOUT option enabled!
 */

static int close_watchdog(void)
{
    int rv = 0;

    if(g_wd_fd1 != -1) {
        rv = write(g_wd_fd1, "V", 1);
        if (rv < 0) {
            int err = errno;
            syslog(LOG_INFO, "write watchdog device gave error %d = '%s'!\n", err, strerror(err));
            rv = -1;
            return rv;
        } else {
            syslog(LOG_INFO, "Close watchdog ok!\n");
        }
    }

    return rv;
}

static int open_watchdog(char *name, int timeout)
{
    struct watchdog_info ident;
    int rv = 0;
    static int open_flag = 0;

    if (name != NULL) {
        if(open_flag) {
            close_watchdog();
        } else {
            open_flag = 1;
            g_wd_fd1 = open(name, O_WRONLY);
            if (g_wd_fd1 == -1) {
                syslog(LOG_INFO, "cannot open %s (errno = %d = '%s')\n", name, errno, strerror(errno));
                rv = -1;
                return rv;
            }
        }
        
        if(timeout) {
            set_watchdog_timeout(timeout);

            /* Also log watchdog identity */
            if (ioctl(g_wd_fd1, WDIOC_GETSUPPORT, &ident) < 0) {
                syslog(LOG_INFO, "cannot get watchdog identity (errno = %d = '%s')\n", errno, strerror(errno));
            } else {
                ident.identity[sizeof(ident.identity) - 1] = '\0';    /* Be sure */
                syslog(LOG_INFO, "hardware watchdog identity: %s\n", ident.identity);
            }
        }
    }

    return rv;
}

/* write to the watchdog device */
static int keep_alive(void)
{
    int err = errno;
    
    if (g_wd_fd1 != -1) {
        if (write(g_wd_fd1, "\0", 1) < 0) {
            syslog(LOG_INFO, "write watchdog device gave error %d = '%s'!\n", err, strerror(err));
        }
    }
    
    return 0;
}

#define DOG_FIFO_NAME "/var/run/dog_fifo"
#define DOG_FIFO_SIZE 64
static int dog_pipe_fd = -1;

static int watchdog_fifo_init(void)
{
    int ret = 0;
    int open_mode = O_RDONLY | O_NONBLOCK;

    unlink(DOG_FIFO_NAME);
    if(access(DOG_FIFO_NAME, F_OK) == -1) {
        ret = mkfifo(DOG_FIFO_NAME, 0777);
        if(ret != 0) {
            syslog(LOG_INFO, "Could not create fifo %s\n", DOG_FIFO_NAME);
            exit(-1);
        }
    }

    dog_pipe_fd = open(DOG_FIFO_NAME, open_mode);
    if(dog_pipe_fd < 0) {
        syslog(LOG_INFO, "Could not open fifo %s\n", DOG_FIFO_NAME);
        exit(-1);
    }
    //printf("Process %d opeining FIFO O_RDONLY | O_NONBLOCK\n", getpid());
    syslog(LOG_INFO, "Process %d opeining FIFO\n", getpid());

    return ret;
}

static int watchdog_fifo_read(void)
{
    int ret = 0;
    int size = 0;
    char fifo_buf[DOG_FIFO_SIZE] = {0};
    int interval = 0;

    size = read(dog_pipe_fd, fifo_buf, DOG_FIFO_SIZE);
    if(size > 0) {
        if(strncmp(fifo_buf, "close", 5) == 0) {
            syslog(LOG_INFO, "Get cmd : close wdog\n");
            close_watchdog();
            ret = 1;
        } else if(strncmp(fifo_buf, "open", 4) == 0) {
            syslog(LOG_INFO, "Get cmd : open wdog\n");
            interval = get_wd_time();
            syslog(LOG_INFO, "get interval %d\n", interval);
            open_watchdog("/dev/watchdog", interval);
            ret = 1;
        }
    }

    return ret;
}
#endif

int feed_watchdog(int wd,int sw)
{    
#if 0
    char cnt;

    if(g_wd_fd1 <= 0)
    {
        g_wd_fd1 = open("/dev/watchdog0", O_RDWR);
        if(g_wd_fd1<0)
            return -1;
    }   
    if(g_wd_fd2 <= 0)
    {
        g_wd_fd2 = open("/dev/watchdog1", O_RDWR);
        if(g_wd_fd2<0)
            return -1;
    }  

    if(sw)
        cnt = get_wd_time();
    else
        cnt = 0;

    if(0 == wd)
        write(g_wd_fd1, &cnt, 1);
    else
        write(g_wd_fd2, &cnt, 1);
#endif

    return 0;
}

void feed_watchdof_handle(void *args)
{
    feed_watchdog(0,1);
}

void* proc_manager_fddog_thread(void *args)
{
    struct shm_area *sa;
    
    sa = getshmst();
    if (NULL == sa)
        return NULL;

    while (!sa->run)
    {
        keep_alive();
        usleep(1000 * 1000); // 1s
    }
    return NULL;
}

void proc_manager_deamon(int num)
{
    struct shm_area *sa;
    int interval = 0;
    int second = 1;
    int loop = 0;
    
    watchdog_fifo_init();

    sa = getshmst();

    if(NULL == sa)
    {   
        return ;
    }

    memset(sa,0, sizeof(struct shm_area));

    init_proc_list();

    interval = get_wd_time();
    printf("get interval %d\n", interval);
#ifdef X86_PLATFORM
    open_watchdog("/dev/watchdog", interval);
#else
    open_watchdog("/dev/watchdog", interval);
#endif

    {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setschedpolicy(&attr, SCHED_RR);
        pthread_create(&g_wd_fdthread, &attr, proc_manager_fddog_thread, NULL);
        pthread_detach(g_wd_fdthread);
        pthread_attr_destroy(&attr);
    }

    struct kp_mgmt kpm;

    while(!sa->run)
    {
        get_keep_proc(&kpm);
        update_all_proc_stat(&kpm);
        //print_running_process();
        
        check_run_led(sa);
        check_alarm_led(sa);
        watchdog_fifo_read();

#if 0
        if(-1 == search_and_restart2(&kpm))
        {
            //stop
            //feed_watchdog(0,0);
            //feed_watchdog(1,0);
        }
        else
        {
            //feed watchdog
            if(interval > 0 && second >= interval) {
                keep_alive();
                second = 1;
                //printf("keep alive\n");
            }
            //feed_watchdog(0,0);
            //feed_watchdog(1,0);
        }

//        destroy_proc_list();

        usleep(200000);   //200ms
        loop++;
        if(loop >= 5) {
            second++;
            loop = 0;
            //printf("loop %d second\n", second);
        }
#else
        if(-1 == search_and_restart2(&kpm))
        {
        }
        else
        {
            keep_alive();
        }
        
        usleep(1000*1000); // 1s
#endif

    }

    shmdt(sa);

   
    mpm_set_run_led(MPM_LED_OFF);
    mpm_set_alarm_led(MPM_LED_OFF);
    deinit_proc_list();
    deinit_pmconfig();
    
}



void Daemonize (void) {
    pid_t pid, sid;

    /* Creates a new process */
    pid = fork();

    if (pid < 0) {
        /* Fork error */
        exit(1);
    } else if (pid == 0) {
        /* Child continues here */

        umask(027);

        sid = setsid();
        if (sid < 0) {
            exit(1);
        }

        return;
    }

    exit(1);
}

#ifdef X86_PLATFORM
void set_process_priority()
{
    struct sched_param param = {};
    int maxRR = sched_get_priority_max(SCHED_RR);

    if(maxRR == -1)
    {
        printf("sched_get_priority_max() failed!\n");
        return;
    }
    
    printf("maxRR: %d\n", maxRR);
    
    param.sched_priority = maxRR;
    
    if(sched_setscheduler(getpid(), SCHED_RR, &param) == -1)
    {
        printf("sched_setscheduler() failed!\n");
    }
    printf("Policy: %d\n", sched_getscheduler(0));
}
#endif

int main(int argc, char *argv[])
{
    pid_t pid = 0;
    int param;
    const char *optstring = "dn:tc:hl";
    const char *default_cfg = "/etc/mpm.conf";
    char cfg_buf[1024] = {0};
    int num = 2; //default
    int len, t = 0;
    int dm = 0;

    while(-1 != (param = getopt(argc, argv, optstring)))
    {
        switch(param){
            case 'n':
                num = atoi(optarg);
                if(num < 1)
                {
                    printf("Process Manager number error\n");
                }
                break;
            case 'h':
                pm_usage(argv[0]);
                exit(0);
            case 't':
                t = 1;
                break;
            case 'c':
                len = strlen(optarg);
                if(len > (int)(sizeof(cfg_buf)-1))
                {
                    printf("Configuration file path too long, it must less than 1023\n");
                    exit(1);
                }
                memcpy(cfg_buf, optarg, len);
                cfg_buf[len] = 0;                
                break;
            case 'd':
                 dm = 1;   
                break;
            default:
                pm_usage(argv[0]);
                exit(1);
        };
    }

    if(optind > argc)
    {
        pm_usage(argv[0]);
        exit(1);
    }

    if(num > MAX_PM_NUM)
    {
        printf("Process manager number must less than %d\r\n", MAX_PM_NUM);
        exit(1);
    }
    
    if(0 == cfg_buf[0])
    {
        len = strlen(default_cfg);
        memcpy(cfg_buf, default_cfg, len);
        cfg_buf[len] = 0;
    }
    
    printf("num %d\n",num);
    printf("cfg_buf %s\n",cfg_buf);

    if (dm) {
        Daemonize();
    }
    
    if(-1 == init_pmconfig(cfg_buf))
    {
        printf("init configuration file error\r\n");
        exit(1);
    }


    // init off the led 
    mpm_set_run_led(MPM_LED_OFF);
    mpm_set_alarm_led(MPM_LED_OFF);

    if(t)
    {
        struct shm_area *sa = getshmst();
        if(!sa)
        {
            printf("Can't get share memory\n");
            exit(1);
        }
        sa->run = 1;
        sa->bypass1 = 1;
        sa->bypass2 = 1;
        shmdt(sa);
        exit(0);
    }
    
#if 0
    while(num --)
    {
        pid = fork();
        if(pid == 0)
        {
            break;
        }
    }
#endif    

    printf("process id is %d, pid %d\r\n", getpid(), pid);
    if(pid > 0)
        return 0;
    
#ifdef X86_PLATFORM
    set_process_priority();
#endif

    proc_manager_deamon(num);
    printf("End.\n");

    return 0;
}


#ifdef __plusplus
}
#endif


