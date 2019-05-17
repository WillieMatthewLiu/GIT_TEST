#ifdef __cplusplus
extern "C"{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pm_config.h"
#include "proc_manager.h"



#define SEG_NAME_LEN 64
#define MAGIC_RET   100

typedef enum {
    E_PROCESS,
    E_SHM_KEY,
    E_KP_CFG_MAX
}KP_CFG_E;

typedef void (*cfg_func)(char *line, void *arg);

struct kp_config{
    char *segname;
    cfg_func f;
};

static int g_cfg_status;                 //KP_CFG_E
static struct kp_mgmt g_skp;
static int kp_shm_key;
static int g_wd_time;




static void load_cfg_process(char *line, void *arg);
static void load_shm_key( char *line, void *arg);
static void load_wd_time( char* line, void *arg);

static void print_cfg();


struct kp_config g_kp_cfg[]={
    {"moniter_process", load_cfg_process},
    {"shm_key", load_shm_key},
    {"watch_dog", load_wd_time},
    {0,0}
};

static char *strim(char *str){
    while(str && isspace(str[0]))
        str++;
    return str;
}

static int chk_status(const char *line)
{
    char *start = NULL;
    char *end   = NULL;
    int arrsize = 0,i, len;

    if(NULL == line)
    {
        return -1;
    }

    start = strchr(line, '[');
    end   = strrchr(line, ']');
    len = end - start - 1;
    if(NULL == start || NULL == end || len <= 0)
    {
        return -1;
    }

    arrsize = sizeof(g_kp_cfg)/sizeof(struct kp_config);

    for(i=0; i<arrsize; i++)
    {
        int slen = strlen(g_kp_cfg[i].segname);
        if(slen == len)
        {
            if(0 == memcmp(g_kp_cfg[i].segname, start+1, len))
                return i;
        }        
    }

    return -1;
    
    
}

static void load_cfg_process(char *line, void *arg)
{
    char *delim = NULL;
    char *process = NULL;
    char *para  = NULL;
    char *saveptr = NULL;
    char *pst=NULL;
    char *ped=NULL;
    int len;
    struct keep_proc *skp;

    if(NULL == line)
        return ;

    if(MAX_PROCESS_NUM == g_skp.n)
        return ;
    skp = &(g_skp.kpm[g_skp.n]);
    
    process = strtok_r(line, ":", &para);
    if(para == NULL || para[0]=='\0')
        return;

    skp->process = strdup(process);

    para = strim(para);
    if(strncmp(para, "env", 3) ==0){
        para+=3;
        if(para[0] != ':' 
            || (pst = strchr(para, '{'))==NULL 
            || (ped = strchr(para, '}'))==NULL
            || pst > ped)
            return;
        len = ped - pst;
        skp->env = malloc(len);
        memset(skp->env, 0, len);
        memcpy(skp->env, pst+1, len-1);

        para=strim(ped+1);
    }
    if(strncmp(para, "param", 5) ==0){
        para+=5;
        if(para[0] != ':' 
            || (pst = strchr(para, '{'))==NULL 
            || (ped = strchr(para, '}'))==NULL
            || pst > ped)
            return;
        len = ped - pst;
        skp->param= malloc(len);
        memset(skp->param, 0, len);
        memcpy(skp->param, pst+1, len-1);

        para=strim(ped+1);
    }else{
        skp->param = strdup(para);
    }

    g_skp.n ++;
    
}
static void load_shm_key( char *line, void *arg)
{
    char *delim = NULL;

    if(NULL == line)
        return ;

    delim = strchr(line, ':');
    if(NULL == delim || 0 == *(delim+1))
        return ;
    kp_shm_key = atoi(delim+1);
        
}

static void load_wd_time( char* line, void *arg)
{
    char *delim = NULL;

    if(NULL == line)
        return ;
    delim = strchr(line, ':');
    if(NULL == delim || 0 == *(delim+1))
        return ;
        
    g_wd_time = atoi(delim+1);
}

int get_wd_time()
{
    return g_wd_time;
};

key_t get_shm_key()
{
    //return (key_t)kp_shm_key;
    return MPM_SHARE_MEMORY_KEY;
}
int get_keep_proc(struct kp_mgmt *kpm)
{
    if(NULL == kpm)
        return -1;
        
    memcpy(kpm, &g_skp, sizeof(g_skp));
    
    return 0;
}

static int handle_pidfile(char *buf, const char *pro)
{
	const char *s_path = "/var/run/";
	const char *s_pid = ".pid";
	char filename[64] = {0};
	
	if(NULL != strstr(buf, pro))
	{
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename), "%s%s%s\0", s_path,  pro, s_pid );
		if(access(filename, F_OK) == 0)
			unlink(filename);
	}
	return 0;
}

int init_pmconfig(const char *filename)
{
    FILE *fp;
    char linebuf[2048];
    int ret;

    if(NULL == filename)
        return -1;
        
    memset(&g_skp, 0, sizeof(g_skp));
    g_cfg_status = 0;
    kp_shm_key = 0;
    g_wd_time = 5;
    //read file
    fp = fopen(filename, "r");
    if(NULL == fp)
        return -1;
    while(NULL != fgets(linebuf,sizeof(linebuf), fp))
    {
        if (strchr(linebuf, '#')) {
	     handle_pidfile(linebuf,"ha");
            continue;
        }
        ret = chk_status(linebuf);
        if(ret < 0)
        {
            g_kp_cfg[g_cfg_status].f(linebuf, NULL);
        }
        else
            g_cfg_status = ret;
    }

    fclose(fp);

    
    print_cfg();
    return 0;
    
}
void deinit_pmconfig()
{
    //nothing to do...
}

static void print_process(struct keep_proc *skp)
{
    if(!skp)
        return;
    if(skp->env)
        printf("%s ", skp->env);
    
    printf("%s ", skp->process);
    
    if(skp->param)
        printf("%s", skp->param);
    
    printf("\n");
        
}
static void print_cfg()
{
    int i;

    printf("total process number: %d\n", g_skp.n);
    for(i=0; i<g_skp.n; i++)
    {
        print_process(&(g_skp.kpm[i]));
    }
    
}

#ifdef __cplusplus
}
#endif


