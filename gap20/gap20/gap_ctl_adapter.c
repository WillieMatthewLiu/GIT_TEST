#include "app_common.h"
#include "command.h"
#include "memory.h"

#include "util-lock.h"
#include "util-list.h"
#include "gap_ctl_adapter.h"
#include "gap_ctl.h"
#include "vty.h"
#include "sockmgr.h"


/* begin---------------add new CTL tunnel  , 2017.1.17 */
int vty_adapter_create(struct vty *vty)
{
	struct vty_adapter *adpts = vty_adapter_init(NULL, OUTER_DEFAULT_IP_STR, GAP_VTY_PORT);

	vty->usr_data = adpts;
}

int vty_adapter_close(struct vty *vty)
{
	struct vty_adapter *adpts = vty->usr_data;
	if (adpts) {
		vty_adapter_deinit(adpts);
		vty->usr_data = NULL;
	}

}
/* end---------------add new CTL tunnel  , 2017.1.17 */


