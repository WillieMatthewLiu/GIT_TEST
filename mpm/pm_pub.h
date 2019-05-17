#ifdef __cplusplus
extern "C"{
#endif

#ifndef __PM_PUB_
#define __PM_PUB_


#define MAX_NAME_LEN 128
#define MAX_ARG_COUNT 16

struct _keep_proc{
    char name[128];    
    int len;
};


typedef enum {
    E_PROC_STAT_MIN=1,
    E_PROC_STAT_R,
    E_PROC_STAT_S,
    E_PROC_STAT_D,
    E_PROC_STAT_Z,
    E_PROC_STAT_T,
    E_PROC_STAT_W,
    E_PROC_STAT_MAX
}PROC_STATUS_E;

struct keep_proc{
    int pid;
    int status;

    char *process;
    char *env;
    char *param;
};





#endif   /*__PM_PUB_*/
#ifdef __cplusplus
}
#endif


