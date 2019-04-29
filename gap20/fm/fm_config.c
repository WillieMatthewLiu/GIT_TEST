//     Pandora FMS Embedded Agent
//     (c) Artica Soluciones Tecnológicas S.L 2011
//     (c) Sancho Lerena <slerena@artica.es>

//     This program is free software; you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation; either version 2 of the License.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.

//
// Config file parser module. 

#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <time.h>
#include "db_agent.h"
#include "fm_type.h"
#include "fm_config.h"
#include "fm_util.h"


#define MAXLEN 1024
#define MAX_EVNTS 1024
static pthread_t epollpid;
static int eplfd;
char* sn;
int sc_flag = 0;

/*
 * initialize data to default values
 */

int
init_parameters (struct agent_setup* pandorasetup)
{
    char *data=NULL;
	asprintf (&pandorasetup->logfile,"/tmp/pandora_agent.log");
	asprintf (&pandorasetup->agent_name, "localhost");
	asprintf (&pandorasetup->server_ip, "localhost");
	pandorasetup->verbosity=5;
    
    eplfd=epoll_create1(0);
    if(eplfd<0){
        perror("epoll_create1() error");
        return-1;
    }

    sn="01234567";

    /*generate all mods configure*/
    data=pandora_exec("/usr/bin/gen_conf.sh");
    pandora_free(data);
    
    return 0;
}

int
fill_agent_setup (struct agent_setup *ps, char *field, char *value)
{
	if (!field)
		return 0;
	if (!*field)
		return 0;
	
	if (strcmp(field, "logfile")==0) {
		pandora_free(ps->logfile);
		asprintf(&ps->logfile, value);
		return 1;
	}
	else if (strcmp(field, "debug")==0) {
		ps->debug=atoi(value);
		return 1;
	}
	else if (strcmp(field, "interval")==0) {
		ps->interval=atoi(value);
		return 1;
	}
	else if (strcmp(field, "autotime")==0) {
		ps->autotime=atoi(value);
		return 1;
	}
	else if (strcmp(field, "verbosity")==0) {
		ps->verbosity=atoi(value);
		return 1;
	}
	else if (strcmp(field, "agent_name")==0) {
		pandora_free(ps->agent_name);
		asprintf(&ps->agent_name, value);
		return 1;
	}
	else if (strcmp(field, "server_ip")==0) {
		pandora_free(ps->server_ip);
		asprintf(&ps->server_ip, value);
		return 1;
	}
	else if (strcmp(field, "temporal")==0) {
		pandora_free(ps->temporal);
		asprintf(&ps->temporal, value);
		return 1;
	}
	else if (strcmp(field, "server_port")==0) {
		ps->server_port=atoi(value);
		return 1;
	}
	else if (strcmp(field, "remote_config")==0) {
		ps->remote_config=atoi(value);
		return 1;
	}
	else
		return 0;
}

int
fill_agent_module (struct agent_module *pm, char *field, char *value)
{
	if (!field)
			return 0;
	if (!*field)
		return 0;
	
	if (strcmp(field, "module_name")==0)
	{
		pandora_free(pm->name);
		asprintf(&pm->name, value);
		return 1;
	}
	if (strcmp(field, "module_type")==0)
	{
		pandora_free(pm->type);
		asprintf(&pm->type, value);
		return 1;
	}
    else if (strcmp(field, "module_exec")==0)
	{
		pandora_free(pm->exec);
		asprintf(&pm->exec, value);
		return 1;
	}
	else if (strcmp(field, "module_interval")==0)
	{
		pm->interval=atoi(value);
		return 1;
	}
	else if (strcmp(field, "module_description")==0)
	{
		pandora_free(pm->description);
		asprintf(&pm->description, value);
		return 1;
	}  
    /*below is optional*/
	else if (strcmp(field, "module_initdelay")==0)
	{
		pm->initdelay=atoi(value);
		return 1;
	}
	else if (strcmp(field, "module_alert")==0)
	{
		pm->alert=atoi(value);
		return 1;
	}
	else if (strcmp(field, "module_warning_type")==0)
	{
		pandora_free(pm->warning_type);
		asprintf(&pm->warning_type, value);
		return 1;
	}    
    else if (strcmp(field, "module_warning_window")==0)
	{
    	pm->warning_window=atoi(value);
    	return 1;
	}
	else if (strcmp(field, "module_warning")==0)
	{
		pm->warning=atoi(value);
		return 1;
	}
	else if (strcmp(field, "module_critical")==0)
	{
		pm->critical=atoi(value);
        
		return 1;
	}
    else if (strcmp(field, "module_warning_gen")==0)
	{
		pm->warning_gen_cnt=atoi(value);
		return 1;
	}
    else if (strcmp(field, "module_alert_rec")==0)
	{
		pm->alert_rec_cnt=atoi(value);
		return 1;
	}
	else if (strcmp(field, "module_condition")==0)
	{
		pandora_free(pm->condition);
		asprintf(&pm->condition, value);
        
		return 1;
	}    
    else if (strcmp(field, "module_warning_exec")==0)
	{
		pandora_free(pm->warning_exec);
		asprintf(&pm->warning_exec, value);
        
		return 1;
	}
    else if (strcmp(field, "module_critical_exec")==0)
	{
		pandora_free(pm->critical_exec);
		asprintf(&pm->critical_exec, value);
        
		return 1;
	}
    else if (strcmp(field, "module_alert_rec_exec")==0)
	{
		pandora_free(pm->alert_rec_exec);
		asprintf(&pm->alert_rec_exec, value);
        
		return 1;
	}
    else
		return 0;
}
#define ALERT_CONTINUE  0x11
#define ALERT_STATISTIC 0x22
#define ALERT_NORMAL    0
#define ALERT_WARNING   1
#define ALERT_CRITICAL  2
#define ALERT_NOTCHANGE 3

char *alert[3]={SYS_EVT_LEVEL_NORMAL,SYS_EVT_LEVEL_WARN,SYS_EVT_LEVEL_CRITICAL};

#define ALERT_GEN 0x5
#define ALERT_REC 0xa
#define INIT_VAL 0xdeadbeef

void destroy_resource()
{
    struct agent_module *ptaux=modlist; 
    while (ptaux!=NULL){
        struct agent_module *pcur=ptaux;  
        if (ptaux->next)
            ptaux=ptaux->next;
        else
            ptaux=NULL;
        
        if (pcur->alert_pstat){
            if (pcur->alert_pstat->chkstats)
                free(pcur->alert_pstat->chkstats);
            free(pcur->alert_pstat);
        }
        free(pcur);
    }       
}

int get_alert_cond(int alert, struct agent_module* pmodule){
    struct module_alert *astat = pmodule->alert_pstat;
    int i,warncnt=0;

    for(i = 0; i < astat->chksize; i++)
    {
        if (astat->chkstats[i] != 0)
        {
            warncnt++;    
        }
    }

    if (warncnt >= pmodule->warning_gen_cnt)
    {
        return ALERT_WARNING;    
    }

    return ALERT_NOTCHANGE;
}

#define DATABASE_LOG      " /data/gap_sqlite3_db.log "
#define SQLITE3_PARAM     "pragma synchronous=\'off\';pragma journal_model=\'memory\';"
#define SYS_EVENT_TABLE   " sys_event_table "
/* sqlite3 test.db "insert into sys_event_table(level, type, content) values('3', '1', 'helloworld')" */
#define log_sysevent(level, desc, arg...)\
do{\
	char cmd[2048];\
	snprintf(cmd, sizeof(cmd), desc, ##arg);\
	cmd[2047]=0;\
	write_sysevent_log(level,SYS_EVT_TYPE,cmd,PRI_HIGH,1);\
}while(0)

void report_alert(int alert_stat, struct agent_module* pmodule)
{
    //char cmdbuf[1024];
    char *cmd=NULL;
    
    log_sysevent(alert[alert_stat],"agent:%s, mod:%s, report alarm status: %s",
                        fm_agent->agent_name, pmodule->name, alert[alert_stat]);
    
    if (alert_stat==ALERT_NORMAL){
        if (pmodule->alert_rec_exec)
            cmd=pmodule->alert_rec_exec;
    }

    if (alert_stat==ALERT_WARNING){
        if (pmodule->warning_exec)
            cmd=pmodule->warning_exec;
    }

    if (alert_stat==ALERT_CRITICAL){
        if (pmodule->critical_exec)
            cmd=pmodule->critical_exec;
    }

    if (cmd)
    {
        char *data=NULL;
        data=pandora_exec(cmd);        
        pandora_free(data);
    }    

}

void clear_check_stats(struct module_alert *alert_pstat)
{
    memset(alert_pstat->chkstats, 0, alert_pstat->chksize*sizeof(int));
    alert_pstat->pos = 0;
    alert_pstat->recnt = 0;
    
    return;
}

void update_check_stats(int check, struct module_alert *alert_pstat)
{    
    if (check == ALERT_CRITICAL){
        clear_check_stats(alert_pstat);
        return;
    }
    
    alert_pstat->chkstats[alert_pstat->pos]=check;
    alert_pstat->pos++;
    alert_pstat->pos=alert_pstat->pos%alert_pstat->chksize;
    
    return;
}

void handle_chk_result(int check, int val, struct agent_module* pmodule){
    struct module_alert *alert_pstat=pmodule->alert_pstat;
    int lastchk,alert_stat = ALERT_NORMAL;
    
    lastchk=alert_pstat->lastchk;
    alert_pstat->lastchk = check;
    
    if (check!=lastchk)
    {
        extern struct agent_setup    *fm_agent;
        FM_LOG("FMS: Agent:%s, module:%s, status change from %s to %s, cur %u, warning %u, critical %u, condition %s",
            fm_agent->agent_name, pmodule->name, alert[lastchk],alert[check],val, 
            pmodule->warning, pmodule->critical,pmodule->condition);                
    }    

    update_check_stats(check,alert_pstat);

    if (check == ALERT_NORMAL)
    {
        if (alert_pstat->reportalert != ALERT_NORMAL){
            if ((alert_pstat->recnt++) >= pmodule->alert_rec_cnt){                
                clear_check_stats(pmodule->alert_pstat);
                /*report check recover*/
                report_alert(ALERT_NORMAL, pmodule);
                alert_pstat->reportalert=ALERT_NORMAL;
            }
        }
        
        return;
    }
    
    /*critical check generates once condition meet one time*/
    if (check==ALERT_CRITICAL){
        alert_stat = ALERT_CRITICAL;
    }else{/*only judge warning or no report*/
        alert_stat = get_alert_cond(check,pmodule);
    }

    if ((alert_stat== ALERT_NOTCHANGE) || (alert_pstat->reportalert == alert_stat))
        return;

    alert_pstat->reportalert = alert_stat;
    /*report check*/
    if (alert_pstat->reportalert != ALERT_NORMAL)
        report_alert(alert_pstat->reportalert, pmodule);
    
    return;
    
}

void* loop_module(void*arg)
{
    struct epoll_event evnts[MAX_EVNTS];
    int n=-1;
    int i=0;
    int epfd=*(int*)arg;
    extern struct agent_setup *fm_agent;

    while(1){
        n=epoll_wait(epfd,evnts,MAX_EVNTS,-1);
        if(n==-1){
            perror("epoll_wait() error");
            break;
        }
        
        // Set pseudorandom number
        fileseed =  pandora_return_unixtime ();
        for(i=0;i<n;i++){
            uint64 buff;
            int r;
            struct TimerEvent* tev=(struct TimerEvent*)(evnts[i].data.ptr);            

            if (!tev) continue;
            r=read(tev->tfd,(void*)&buff,sizeof(buff));
            (void)r;
            if (!sc_flag)
            {
                char *data;
                int val,check=ALERT_NORMAL;
                struct agent_module* pmodule = tev->pmodule;
                    
                data=tev->cbf(tev->args);
                if (!pmodule->alert)
                    continue;
                
            	trim(data);
                val=atoi(data);                
                pandora_free(data);
                if (!strcmp(pmodule->condition,"-")){
                    if (pmodule->warning != INIT_VAL){
                        if (val <= pmodule->warning)
                            check=ALERT_WARNING;
                    }
                    
                    if (pmodule->critical != INIT_VAL){
                        if (val <= pmodule->critical){
                            check=ALERT_CRITICAL;
                        }
                    }
                }else if (!strcmp(pmodule->condition,"=")){
                    if (pmodule->warning != INIT_VAL){
                        if (val == pmodule->warning)
                            check=ALERT_WARNING;
                    }
                    
                    if (pmodule->critical != INIT_VAL){
                        if (val == pmodule->critical){
                            check=ALERT_CRITICAL;
                        }
                    }
                }else{
                    if (pmodule->warning != INIT_VAL){
                        if (val >= pmodule->warning)
                            check=ALERT_WARNING;
                    }
                    
                    if (pmodule->critical != INIT_VAL){
                        if (val >= pmodule->critical){
                            check=ALERT_CRITICAL;
                        }
                    }
                }
                
                handle_chk_result(check,val,pmodule);
            }else{
                char* xml_filename;
                xml_filename = pandora_write_xml_disk (fm_agent, tev->pmodule);
                if (fm_agent->debug == 1){
                    printf ("Debug mode activated. Exiting now! \n");
                    exit (0);
                }
                (void)xml_filename;
            }
        }
    }

    close(epfd);
    pthread_exit(NULL);
}

int create_timerfd(int initdelay, int interval)
{
    struct timespec now;
    struct itimerspec its;
    int tfd=timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK);

    if(tfd<0){
        perror("timerfd_create() error");
        return -2;
    }

    if(clock_gettime(CLOCK_MONOTONIC,&now)!=0){
        perror("clock_gettime() error");
        return -1;
    }
    
    its.it_value.tv_sec=now.tv_sec+initdelay;
    its.it_value.tv_nsec=0;
    its.it_interval.tv_sec=interval;
    its.it_interval.tv_nsec=0;

    if(timerfd_settime(tfd,TFD_TIMER_ABSTIME,&its,NULL)!=0){
        perror("timerfd_settime() error");
        return -1;
    }
    
    return tfd;
}

int add_tev2epoll(struct TimerEvent* tev, int epfd)
{
    struct epoll_event ev;

    ev.events=EPOLLIN|EPOLLET;
    ev.data.ptr=tev;
    if(epoll_ctl(epfd,EPOLL_CTL_ADD,tev->tfd,&ev)!=0){
        perror("epoll_ctl() error");
        return -1;
    }

    return 0;
}

void default_modopt(struct agent_module *pm)
{
    pm->warning_gen_cnt = 1;
    pm->alert_rec_cnt   = 1;    
    pm->warning = INIT_VAL;
    pm->critical= INIT_VAL;    
    asprintf(&pm->condition, "+");
}

void config_alertopt(struct agent_module *pm)
{
    if ((pm->warning==INIT_VAL) && (pm->critical==INIT_VAL))
    {
        printf("module %s's module_warning or critical must config 1 at least\n",pm->name);
        destroy_resource();
        exit(-1);
    }
#if 0
    if ((!pm->warning_exec) && (!pm->critical_exec))
    {
        printf("module %s's module_warning or critical's exec must config 1 at least\n",pm->name);
        destroy_resource();
        exit(-1);
    }
#endif    
    pm->alert_pstat=(struct module_alert*) calloc (sizeof(struct module_alert), 1);
	if (pm->alert_pstat == NULL)
	{
		printf ("Error on calloc pm->alert_pstat\n");
        destroy_resource();
		exit(-1);
	}
    
    pm->alert_pstat->chksize=pm->warning_gen_cnt;

    if (pm->warning_type)
    {
        if (!strcmp(pm->warning_type,"statistics"))
        {
            if (!pm->warning_window){
                printf("module %s's module_alert_type is statistics, module_alert_window must config\n",pm->name);
                destroy_resource();
                exit(-1);
            }        
            pm->alert_pstat->chksize=pm->warning_window;
        }
    }

    
    pm->alert_pstat->chkstats=(int*)calloc(sizeof(int), pm->alert_pstat->chksize);
	if (pm->alert_pstat->chkstats == NULL)
	{
		printf ("Error on calloc alert status\n");
        destroy_resource();
		exit(-1);
	}
    

}

int add_mod2epoll(struct agent_module *pm, int epfd)
{
    int tfd,ret;
    struct TimerEvent *tev;
    int initdelay=pm->initdelay;
    int interval=pm->interval;
    
    tfd=create_timerfd(initdelay, interval);
    if (!tfd)
    {
        perror("create_timerfd error");
        return -1;        
    }

	tev = (struct TimerEvent *)calloc(sizeof(struct TimerEvent), 1);
	if (tev == NULL)
	{
		perror ("Error on calloc tev\n");
		exit(-1);
	}

    tev->tfd=tfd;
    tev->cbf=pandora_exec;
    tev->args=pm->exec;
    tev->pmodule=pm;
    ret=add_tev2epoll(tev,epfd);
    if (ret)
    {
        perror("create_timerfd error");
        return -1;
    }

    return 0;
}

int
parse_config (struct agent_setup *pandorasetup, struct agent_module **list , char *config_file)
{
	char *line=NULL;
	char *auxline=NULL;
	char buff[MAXLEN];
	char *field=NULL;
	char *value=NULL;
	struct agent_module *module;
	FILE *fileconfig;

	//Open .conf file in read-only mode
	fileconfig = fopen (config_file, "r");
	//If there is an error opening the config file
	if (fileconfig == NULL)
	{
		printf ("Error opening '%s'\n",config_file);
		exit(-1);
	}

	//Get full line
	line = (char*) calloc(MAXLEN, sizeof(char));
	if (line == NULL)
	{
		printf ("Error on calloc'\n");
		exit(-1);
	}
	line = fgets (buff, sizeof(buff), fileconfig);

	while (!feof(fileconfig))
	{
		if (buff[0] != '#' && !isspace(buff[0])) //Skip commented and blank lines
		{
			asprintf(&auxline, line);
			asprintf (&field, strtok (auxline, " \t\r\v\f"));
			trim(field);
			if (strchr (line, ' ')!=NULL)
			{
				asprintf(&value, strchr (line, ' '));
				trim(value);
			}
			//START TO GET MODULE LINES
			if (strcmp (field, "module_begin")==0)
			{
				module = (struct agent_module*) calloc (1, sizeof(struct agent_module));
				if (module == NULL)
				{
					printf ("Error on calloc'\n");
					exit(-1);
				}
                default_modopt(module);
				line = fgets (buff, sizeof(buff), fileconfig); //Get next full line
				asprintf(&auxline, line);
				asprintf (&field, strtok (auxline, " \t\r\v\f"));
				trim(field);
				while (strcmp(field, "module_end")!=0)
				{
					if (strchr (line, ' ')!=NULL)
					{
						asprintf(&value, strchr (line, ' '));
						trim(value);
					}
					fill_agent_module (module, field, value);
					line = fgets (buff, sizeof(buff), fileconfig);
					asprintf(&auxline, line);
					asprintf (&field, strtok (auxline, " \t\r\v\f"));
					trim(field);
				}

                if ((!module->interval) || (!module->exec)){
                    printf("module %s's module_exec or module_interval must config\n",module->name);
                    destroy_resource();
                    exit(-1);
                }                                    

                //LINKED LIST
                if (*list==NULL){
                    *list=module;
                    module->next=NULL;
                }else{
                    struct agent_module *ptaux=*list; 
                    while (ptaux->next!=NULL)
                        ptaux=ptaux->next;
                    
                    ptaux->next=module; 
                    module->next=NULL;
                }
                
                if (module->alert)
                    config_alertopt(module);
                
                add_mod2epoll(module,eplfd);                
                pandorasetup->modnum++;
			} //END OF GETTING MODULE LINES
			else if (strcmp(field, "module_plugin")==0)
			{
				module = (struct agent_module*) calloc (1, sizeof(struct agent_module));
				if (module == NULL)
				{
					printf ("Error on calloc'\n");
					exit(-1);
				}
				fill_agent_module(module, field, value);
			}
			else
			{
				fill_agent_setup(pandorasetup, field, value);
			}
		}
		line = fgets (buff, sizeof(buff), fileconfig);
	}
	pandora_free(line);
	pandora_free(auxline);
	pandora_free(field);
	pandora_free(value);
	//END READING .CONF FILE
	
	fclose(fileconfig);

    if(pthread_create(&epollpid,NULL,loop_module,&eplfd)!=0){
        perror("pthread_create() error");
        return -1;
    }
    
	return 0;
}

