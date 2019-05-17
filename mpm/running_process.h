/*
Author:Rickey
Date: 2014/11/27
Desc: for keep process alive
*/
#ifdef __cplusplus
extern "C"{
#endif

#ifndef __RUNNING_PROCESS_H_
#define __RUNNING_PROCESS_H_

#include "list.h"
#include "pm_pub.h"


struct proc_node{
    list_node ltnext;
    struct keep_proc kpm;
};


struct proc_list{
    int n;
    list_node ltn;
};

extern int init_proc_list();

extern void destroy_proc_list();

extern void print_running_process();
extern void deinit_proc_list();




#endif  /*__RUNNING_PROCESS_H_*/

#ifdef __cplusplus
}
#endif


