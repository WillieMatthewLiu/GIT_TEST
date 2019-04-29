#ifndef _GAP_CMD_STATE_H
#define _GAP_CMD_STATE_H
#include "util-list.h"
#include "util-mem.h"
#include "oscall.h"

void state_conf_cmd_init(void);
void state_show_cmd_init(unsigned int machine);
void state_init(void);
void state_exit(void);

#endif 
