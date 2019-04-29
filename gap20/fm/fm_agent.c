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


#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h> 
#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include "db_agent.h"
#include "fm_type.h"
#include "fm_util.h"
#include "fm_config.h"


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#define PACKAGE_NAME "fault manager"
#define VERSION "0.01"
#define CONF_FILE "/etc/fm/fm_agent.conf"
struct agent_setup    *fm_agent=NULL;
struct agent_module   *modlist=NULL;

int 
main(int argc, char **argv) {
	char					*fullpath=NULL;
	char					*buffer=NULL;
    int ret;

    daemon(0,0);
	FM_LOG("FMS Embedded Agent v%s (c) 2011 http://pandorafms.org\n", VERSION);
    
	ret = db_log_init();
	if (ret != 0)
	{
		FM_LOG("db_log_init: %d", ret);
		return ret;
	}

	modlist=NULL;

	fm_agent = malloc(sizeof(struct agent_setup));
	fm_agent->logfile=NULL;
	fm_agent->agent_name=NULL;
	fm_agent->server_ip=NULL;
	fm_agent->temporal=NULL;
	fm_agent->sancho_test=NULL;

	// Initialize to default parameters
	init_parameters (fm_agent);

	// Load config file using first parameter
  	parse_config (fm_agent, &modlist, CONF_FILE);
	
	FM_LOG ("Starting %s v%s", PACKAGE_NAME, VERSION);
	FM_LOG ("Agent name: %s", fm_agent->agent_name);
	FM_LOG ("Server IP: %s", fm_agent->server_ip);
	FM_LOG ("Temporal: %s", fm_agent->temporal);

    (void)fullpath;
    (void)buffer;
    pause();
    (void)db_log_exit();
	return (0);
}
