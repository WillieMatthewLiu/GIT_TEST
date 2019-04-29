#include <zebra.h>
#include <command.h>
#include "app_common.h"

#include "util-lock.h"
#include "util-list.h"
#include "gap_ctl_adapter.h"
#include "gap_ctl.h"
#include "vty.h"
#include "md5.h"

#include "ha.h"
#include "gap_ctl_ha.h"

#include "db_mysql.h"

#define GAP_CTL_CONTROL_NAME "/dev/gap_ioctl_file"
#define GAP_CTL_CMD_INFO 			('U'<<24 | 'R'<<16 | 'L' <<8 | 'A')
#define GAP_CTL_CMD_ARP_REJECT      GAP_CTL_CMD_INFO+1
#define GAP_OUTER_MOD_ID ((0x0301<<16)|GAP_VTY_PORT)
#define GAP_INNER_MOD_ID ((0x0302<<16)|GAP_VTY_PORT)

static int ha_state = ha_master;

int get_hastate(void)
{
	return ha_state;
}

static void knl_arp_enable(void)
{	
	int fd = open(GAP_CTL_CONTROL_NAME, O_RDWR);
	if (fd <= 0)
	{
		return;
	}
		
	int ok = 0;
	ioctl(fd, GAP_CTL_CMD_ARP_REJECT, &ok);
	close(fd);

	SCLogInfo("Call knl_arp_enable ok.");

	return;
}

static void knl_arp_disable(void)
{	
	int fd = open(GAP_CTL_CONTROL_NAME, O_RDWR);
	if (fd <= 0)
	{
		return;
	}
		
	int ok = 1;
	ioctl(fd, GAP_CTL_CMD_ARP_REJECT, &ok);
	close(fd);

	SCLogInfo("Call knl_arp_disable ok.");

	return;
}

static int gap_event_cb(HAEvent event, void* param)
{
	SCLogInfo("%s\n", ha_event_to_str(event));

	switch (event)
	{
	case HA_EVENT_GO_ACT:
		knl_arp_enable();
		ha_state = ha_master;
		break;

	case HA_EVENT_GO_OOS:
	case HA_EVENT_GO_OOS_NORMAL:
	case HA_EVENT_GO_OOS_FORCED:
		break;

	case HA_EVENT_GO_STB:
		knl_arp_disable();
		ha_state = ha_slave;
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

int gap_ha_init(int machine)
{
	if (machine == outer_machine) 
	{
		int ret = ha_app_register(GAP_OUTER_MOD_ID, 0, gap_event_cb, NULL, NULL);
		if (HA_SUCCESS != ret && HA_ERROR_EXIST != ret) 
		{
			SCLogInfo("Call ha_app_register failed.");
			return -1;
		}

		SCLogInfo("Call ha_app_register ok[%d].", ret);
	}
	else
	{
		int ret = ha_app_register(GAP_INNER_MOD_ID, 0, gap_event_cb, NULL, NULL);
		if (HA_SUCCESS != ret && HA_ERROR_EXIST != ret) 
		{
			SCLogInfo("Call ha_app_register failed.");
			return -1;
		}

		SCLogInfo("Call ha_app_register ok[%d].", ret);
		ha_app_register_finish_notify();
	}

	return 0;
}