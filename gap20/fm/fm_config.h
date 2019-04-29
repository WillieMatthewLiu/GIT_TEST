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


int
init_parameters (struct agent_setup* fm_agent);

int
fill_agent_setup (struct agent_setup *ps, char *field, char *value);

int
fill_agent_module (struct agent_module *pm, char *field, char *value);

int
parse_config (struct agent_setup *pandorasetup, struct agent_module **list, char *config_file);

typedef char* (*CALLBACK_FN)(char*);
struct TimerEvent{
    int tfd;
    CALLBACK_FN cbf;
    char *args;
    struct agent_module* pmodule;
};

