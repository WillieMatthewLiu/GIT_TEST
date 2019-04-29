#ifndef _GAP_ARBITER_HA_H_
#define _GAP_ARBITER_HA_H_

enum gap_ha_state
{
	ha_master,
	ha_slave
};

int gap_ha_init(int machine);
int get_hastate(void);

#endif

