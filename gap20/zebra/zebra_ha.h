#ifndef _ZEBRA_HA_
#define _ZEBRA_HA_
#define ZEBRA_APP_ID ((board_type<<16)|(ZEBRA_VTY_PORT))

int zebra_warm_sync_cmd(struct vty *vty, int ret);
int zebra_ha_init();
#endif
