/*
Author:Rickey
Date: 2014/11/27
Desc: for keep process alive
*/

#ifdef __cplusplus
extern "C"{
#endif

#ifndef __PM_CONFIG_H__
#define __PM_CONFIG_H__

#include <sys/ipc.h>
#include <sys/shm.h>
#include "pm_pub.h"

#define MAX_PROCESS_NUM 16

struct kp_mgmt{
    int n;
    struct keep_proc kpm[MAX_PROCESS_NUM];
};


extern key_t get_shm_key();
extern int get_keep_proc(struct kp_mgmt *skp);
extern int get_wd_time();

extern int init_pmconfig(const char *filename);
extern void deinit_pmconfig();


#endif /*__PM_CONFIG_H__*/

#ifdef __cplusplus
}
#endif


