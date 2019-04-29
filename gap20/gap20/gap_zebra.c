#include "zebra.h"
#include "zclient.h"
#include "command.h"

#include "app_common.h"
#include "gapconfig.h"
#include "main_inouter.h"

static struct zclient *zclient;

void disable_gso(char *phyname)
{
	char cmd[128];
	sprintf(cmd, "ethtool -K %s gso off;ethtool -K %s gro off;", phyname, phyname);
	cmd_system_novty(cmd);
}

int vty_oninterface_add(struct interface *ifp)
{
	SCLogInfo("add interface: %s", ifp->name);
	array_add(g_gapcfg->eths, ifp);
	if (ifp->info == NULL)
		gapconfig_interface_initext(ifp);
	return 0;
}
int vty_oninterface_delete(struct interface *ifp)
{
	SCLogInfo("delete interface: %s", ifp->name);
	array_find_and_remove(g_gapcfg->eths, ifp);
	gapconfig_interface_freeext(ifp);
	return 0;
}
int vty_oninterface_address_add(struct connected *ifc)
{
	struct interface *ifp;

	char strip[100];
	struct if_ext *ext;


	if (ifc->address->family != AF_INET)
	{
		SCLogInfo("on vty_oninterface_address_add, if: %s, not ipv4, return", ifc->ifp->name);
		return 0;
	}
	addr2str(ifc->address->u.prefix4.s_addr, strip);

	ifp = gapconfig_get_if_by_name(ifc->ifp->name);
	if (ifp == NULL)
	{
		SCLogInfo("on vty_oninterface_address_add, if: %s, can't get_if_by_name, return", ifc->ifp->name);
		return 0;
	}
	ext = ifp->info;

	if (ifc->label == NULL || strchr(ifc->label, ':') == NULL)
	{
		SCLogInfo("on vty_oninterface_address_add, if: %s, label: %s, ip: %s", ifp->name, ifc->label, strip);
		array_add(ext->ips, ifc);
		return 0;
	}

	SCLogInfo("on vty_oninterface_address_add, if: %s, label: %s, vip: %s", ifp->name, ifc->label, strip);
	array_add(ext->vips, ifc);
	vtyhlp_sendiptokernel(ifp->name, strip, 0);

	// relisten servers
	for (int j = 0; j < array_count(ext->routes); j++)
	{
		struct route_item *route = array_getat(ext->routes, j);
		if (route->in_port == 0)
			continue;
		if (strlen(route->vtyroute->entryip) == 0 && array_count(ext->vips) == 1)
			strncpy(route->vtyroute->entryip, strip, sizeof(route->vtyroute->entryip));
		if (strcmp(route->vtyroute->entryip, strip) != 0)
			continue;
		vtyhlp_applyroute(route);
	}
	return 0;
}
int vty_oninterface_address_delete(struct connected *ifc)
{
	struct interface *ifp;
	struct if_ext *ext;
	char strip[20];

	if (ifc->address->family != AF_INET)
		return 0;
	addr2str(ifc->address->u.prefix4.s_addr, strip);

	ifp = gapconfig_get_if_by_name(ifc->ifp->name);
	if (ifp == NULL)
		return 0;
	ext = ifp->info;

	if (ifc->label == NULL || strchr(ifc->label, ':') == NULL)
	{
		SCLogInfo("on vty_oninterface_address_delete, if: %s, label: %s, ip: %s", ifp->name, ifc->label, strip);
		array_find_and_remove(ext->ips, ifc);
		return 0;
	}

	SCLogInfo("on vty_oninterface_address_delete, if: %s, label: %s, vip: %s", ifp->name, ifc->label, strip);
	vtyhlp_sendiptokernel(ifp->name, strip, 1);
	vtyhlp_closeall_byaddr(ifp, strip);
	array_find_and_remove(ext->vips, ifc);
	return 0;
}


/* Inteface link up message processing. */
int gap_interface_up(int command, struct zclient *zclient, zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct interface *ifp;

	/* zebra_interface_state_read() updates interface structure in iflist. */
	s = zclient->ibuf;
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	return 0;
}

/* Inteface link down message processing. */
int
gap_interface_down(int command, struct zclient *zclient,
	zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct interface *ifp;

	/* zebra_interface_state_read() updates interface structure in iflist. */
	s = zclient->ibuf;
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;


	return 0;
}

/* Inteface addition message from zebra. */
int
gap_interface_add(int command, struct zclient *zclient, zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (ifp == NULL)
		return 0;

	/* we will disable gso for crypto(guangtie mode),  maybe we can change it after ssl channle stable. */
	disable_gso(ifp->name);

	vty_oninterface_add(ifp);

	return 0;
}

int
gap_interface_delete(int command, struct zclient *zclient,
	zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;

	s = zclient->ibuf;
	/*  zebra_interface_state_read() updates interface structure in iflist */
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	if (if_is_up(ifp)) {
	}

	ifp->ifindex = IFINDEX_INTERNAL;

	vty_oninterface_delete(ifp);

	return 0;
}

int
gap_interface_address_add(int command, struct zclient *zclient,
	zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;
	struct interface *ifp;

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
		zclient->ibuf, vrf_id);
	if (c == NULL)
		return 0;

	ifp = c->ifp;
	if (ifp == NULL)
		return 0;

	vty_oninterface_address_add(c);

	return 0;
}

int
gap_interface_address_delete(int command, struct zclient *zclient,
	zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
		zclient->ibuf, vrf_id);

	if (ifc)
	{
		vty_oninterface_address_delete(ifc);
		connected_free(ifc);
	}

	return 0;
}
static void
ipm_zebra_connected(struct zclient *zclient)
{
	zclient_send_requests(zclient, VRF_DEFAULT);
}

void zebra_init(struct thread_master *master)
{
	/* Allocate zebra structure. */
	zclient = zclient_new(master);
	zclient_init(zclient, ZEBRA_ROUTE_GAP);
	zclient->zebra_connected = ipm_zebra_connected;
	zclient->interface_up = gap_interface_up;
	zclient->interface_down = gap_interface_down;
	zclient->interface_add = gap_interface_add;
	zclient->interface_delete = gap_interface_delete;
	zclient->interface_address_add = gap_interface_address_add;
	zclient->interface_address_delete = gap_interface_address_delete;
}

