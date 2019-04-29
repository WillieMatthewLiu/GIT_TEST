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

// Structs for Pandora Agent
#if 0
struct pandora_agent {
	char *name;
	char *version;
	char *timestamp;
	char *os;
	char *os_version;
	char *os_build;
//	long unsigned int interval;
};
#endif

struct module_alert {
    int* chkstats;      /*alert status*/
    int lastchk;        /*last alert status*/
    int chksize;        /*alert statistics count*/
    int pos;            /*cur alert status save postion*/
    int reportalert;    /*status of reporting alert */
    int recnt;          /*check normal counts after report warning or critical*/
};

struct agent_module {
	char *name;
	char *type;
	char *description;
	char *exec;
	char *plugin;
	int initdelay;
	int interval;
    int alert;
    char *warning_type;
    int warning_window;
    int warning;
    int critical;
    int warning_gen_cnt;
    int alert_rec_cnt;
    char *condition;
    char *warning_exec;    
    char *critical_exec;
    char *alert_rec_exec;
    struct module_alert *alert_pstat;
	struct agent_module *next;    
};

struct agent_setup {
	char *logfile;
	int  debug;
	int  interval;
	int  autotime;
	int  verbosity;
	char *agent_name;
	char *server_ip;
	char *temporal;
	int server_port;
	int remote_config;
	char *sancho_test;
    int modnum;
};

extern struct agent_setup    *fm_agent;

