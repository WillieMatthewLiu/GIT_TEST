#ifdef __cplusplus
extern "C"{
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include "pm_config.h"
#include "running_process.h"


#define MAX_PROC_LIST_NUM 512

static struct proc_list g_free_list_head;
static struct proc_list *g_proc_list;


static char proc_status_c[]={'I', 'R','S','D','Z','T','W','X'};


void deinit_proc_list();


int init_proc_list()
{
    int i;
    struct proc_list *pl;
    struct proc_node *pn;


    g_proc_list = (struct proc_list *)malloc(sizeof(struct proc_list));
    if(NULL == g_proc_list)
        return -1;
    g_proc_list->n = 0;
    list_init(&g_proc_list->ltn);

    pl = (struct proc_list *)(&g_free_list_head);

    pl->n = 0;
    list_init(&pl->ltn);

    for(i=0; i<MAX_PROC_LIST_NUM; i++)
    {
        pn = (struct proc_node *)malloc(sizeof(struct proc_node));
        if(NULL == pn)
        {
            deinit_proc_list();
            return -1;
        }
        memset(pn, 0, sizeof(struct proc_node));
        list_init(&pn->ltnext);
        swlist_add(&pn->ltnext,&pl->ltn);
        pl->n ++;
    }
    
    return 0;
    
}

void deinit_proc_list()
{
    list_node *savptr = NULL,*ele = NULL;
    struct proc_node *pn;

    list_for_safe_each(ele,savptr,&g_free_list_head.ltn)
    {
        pn = list_entity(ele,struct proc_node ,ltnext);
        list_del(ele);
        free(pn);
    }
    g_free_list_head.n = 0;

    list_init(&g_free_list_head.ltn);

    if(g_proc_list)
    {

        list_for_safe_each(ele,savptr,&g_proc_list->ltn)
        {
            pn = list_entity(ele,struct proc_node ,ltnext);
            list_del(ele);
            free(pn);
        }
     
        free(g_proc_list);
        g_proc_list = NULL;
    }
}

static struct proc_node *proc_malloc()
{
    struct proc_node *pn;
    
    if(swlist_empty(&g_free_list_head.ltn))
    {
        return NULL;
    }

    pn = list_entity((g_free_list_head.ltn).next,struct proc_node ,ltnext);

    list_del_init(&pn->ltnext);
    g_free_list_head.n --;

    return pn;   
}


static void proc_free(struct proc_node *pn)
{
    if(!pn)
        return;
    list_init(&pn->ltnext);

    swlist_add(&pn->ltnext, &g_free_list_head.ltn);
    g_free_list_head.n ++;
}

void get_proc_status(char *buf, int *status)
{
    char *p, *savptr=NULL;
    int i=0;

    p = strtok_r(buf, " ", &savptr);
    while(p)
    {
        if(3 == (++i))
        {
            break;
        }
        p = strtok_r(NULL, " ", &savptr);
    }

    switch (*p)
    {
            case 'r':
            case 'R': *status = E_PROC_STAT_R; break;
            case 's':
            case 'S': *status = E_PROC_STAT_S; break;
            case 'd':
            case 'D': *status = E_PROC_STAT_D; break;
            case 'z':
            case 'Z': *status = E_PROC_STAT_Z; break;
            case 't':
            case 'T': *status = E_PROC_STAT_T; break;
            case 'w':
            case 'W': *status = E_PROC_STAT_W; break;
            default:
            *status = E_PROC_STAT_MAX;
    }
        
}


void destroy_proc_list()
{
    struct proc_node *pn;
    list_node *savptr = NULL,*ele = NULL;
    
    if(!g_proc_list)
    {
        return;
    }

    list_for_safe_each(ele,savptr,&g_proc_list->ltn)
    {
        pn = list_entity(ele,struct proc_node ,ltnext);
        list_del(ele);
        proc_free(pn);
    }
 
    list_init(&g_proc_list->ltn);
    g_proc_list->n = 0;
    
}

static void print_proc_node(struct proc_node *pn)
{
    int i;
    
    if(!pn)
    {
        return ;
    }

    printf("%d\t",pn->kpm.pid);
    printf("%c\t",proc_status_c[pn->kpm.status]);
    if(pn->kpm.env)
        printf("%s ", pn->kpm.env);
    printf("%s ",pn->kpm.process, pn->kpm.param);
    if(pn->kpm.param)
        printf("%s", pn->kpm.param);
    printf("\n");
    
}

void print_running_process()
{
    list_node *element;
    struct proc_node *pn;
    
    printf("free list %d\n",g_free_list_head.n);
    printf("total process %d\n",g_proc_list->n);
    
    printf("pid\tstatus\targc\tprocess\n");
    list_for_each(element,&g_proc_list->ltn)
    {
        pn = list_entity(element,struct proc_node ,ltnext);
        
        print_proc_node(pn);
        
    }
}

int update_proc_stat(pid_t pid, struct keep_proc* kpm)
{
    int fd, len;
    char statbuf[128] = {0};
    char contentbuf[1024] = {0};

    sprintf(statbuf, "/proc/%d/stat", pid);
    
    fd = open(statbuf, O_RDONLY);
    if(fd == -1)
    {
        return -1;
    }
    memset(contentbuf, 0, sizeof(contentbuf));
    len = read(fd, contentbuf, sizeof(contentbuf)-1);

    close(fd);
    if(len <= 0)
    {
        return -1;
    }

    get_proc_status(contentbuf, &kpm->status);	
//	printf("pid %d status is %d \n", pid, kpm->status);
	
	return 0;
}

int update_all_proc_stat(struct kp_mgmt* kpm)
{
    int i;
    FILE *fp;
    int cnt = 0;
    pid_t pid = 0;
    char cmd[128];
    struct keep_proc *kp;

    for (i = 0; i < kpm->n; i++)
    {
        kp = &kpm->kpm[i];
        snprintf(cmd, 128, "pidof %s", kp->process);
        fp = popen(cmd, "r");
        if(fp == NULL){
            kp->status = E_PROC_STAT_MIN;
            continue;
        }
        pid = 0;
        fscanf(fp, "%d", &pid);
        fclose(fp);
        if(pid)
            update_proc_stat(pid, kp);
        else
            kp->status = E_PROC_STAT_MIN;
    }
	

    return 0;
}



#ifdef __cplusplus
}
#endif


