

#include <zebra.h>
#include "zserv.h"

#include "threads.h"
#include "lib/memory.h"
#include "command.h"
#include "vty.h"
#include "ha.h"
#include "ha_agent.h"
#include "zebra_ha.h"


extern int board_type;
//extern char *config_file;
//extern char *config_default_dir;

struct vty_adapter *stb_adpt=NULL;


static void zebra_ha_sync_recv_cb(uint32_t app_mod_id, const char *pData, uint32_t len)
{
    
}


int zebra_warm_sync_cmd(struct vty *vty, int ret)
{
    char *cp;
    /* if command execute return fail, dont send to backup */
    if(ret != CMD_SUCCESS)
        return 0;

    /* we will ignore show command */
    cp = vty->buf;
    while(isspace(*cp))
        cp++;
    if(strncmp(cp, "show", 4) == 0)
        return 0;
    
	if (HA_SUCCESS != ha_data_sync(ZEBRA_APP_ID, (const char*)vty->buf, strlen(vty->buf))){
		zlog_err("Call ha_data_sync failed.");
        return -1;
	}

    return 0;
}

void zebra_cold_sync()
{
}


static int zebra_ha_event_cb(HAEvent event, void *param)
{
    switch(event)
    {
        case HA_EVENT_GO_ACT:
            break;
        case HA_EVENT_GO_OOS:
        case HA_EVENT_GO_OOS_NORMAL:
        case HA_EVENT_GO_OOS_FORCED:
			break;
		case HA_EVENT_GO_STB:
            break;
        case HA_EVENT_STB_UP:
            break;
        case HA_EVENT_PEER_CONN_OK:
            break;
        
        default:
            break;
    }
    return 0;
}

int zebra_ha_init()
{
    ha_app_register(ZEBRA_APP_ID, 0, zebra_ha_event_cb, zebra_ha_sync_recv_cb, NULL);
    return 0;
}


