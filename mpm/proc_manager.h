/*
Author:Rickey
Date: 2014/11/27
Desc: for keep process alive
*/

#ifdef __cplusplus
extern "C"{
#endif

#ifndef __PROC_MANAGER_H__
#define __PROC_MANAGER_H__

#define MAX_PM_NUM 8

#define MPM_SHARE_MEMORY_KEY 9876

struct pm_self{
    int root;       // 1 is root pm, other is 0
    int pid;        // process manager identity
};

struct shm_area{
    int run;        // 1 is running
    int num;        // how maney pm is started
    int shkey;      // share memory key
    int rootid;     // root pm lable 
    int run_led1;   // for first run led set
    int run_led2;   // for second led set
    int alarm_led1; //for first alarm led set
    int alarm_led2; //for second alarm led set
    int bypass1;
    int bypass2;
    struct pm_self pm[MAX_PM_NUM];
};


#endif /*__PROC_MANAGER_H__*/

#ifdef __cplusplus
}
#endif


