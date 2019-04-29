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

#include "app_common.h"
#include "util-lock.h"
#include "util-list.h"
#include "util-debug.h"

#define FM_LOG(...) SCLogInfo(__VA_ARGS__)

void
pandora_free (void *pointer);

char *
rtrim(char* string, char junk);

char *
ltrim(char *string, char junk);

char *
trim (char * s);

int
isdatafile (char *filename);


char *
return_time (char *formatstring);


char *
pandora_exec (char *commandline);

char * 
pandora_write_xml_disk (struct agent_setup *pandorasetup, struct agent_module *modlist);

int
pandora_return_unixtime ();

extern int fileseed;

typedef unsigned long long uint64;

// External reference to GNU asprintf, warning messages could be so nasty...:->
extern int asprintf (char **__restrict __ptr, __const char *__restrict __fmt, ...);
extern struct agent_module   *modlist;

