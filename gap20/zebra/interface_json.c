
#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "command.h"
#include "lib/memory.h"
#include "ioctl.h"
#include "connected.h"
#include "log.h"
#include "zclient.h"
#include "vrf.h"
#include "command.h"

#include "thread.h"

#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/irdp.h"

#include "zebra/zebra_ha.h"
#include "json-c.h"

extern struct thread_master *master;
extern int board_type;
extern const char* bond_mode_tbl[];

#define MAC2STR(mac, str, len) \
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X", \
        mac[0],mac[1], mac[2], mac[3], mac[4], mac[5]);

const char *json_format_interface(struct interface *ifp, struct json_object *jobj)
{
    struct listnode *node;
    struct connected *ifc;
    struct zebra_if *zif = ifp->info;

    char mac_str[20];

    MAC2STR(ifp->hw_addr, mac_str, 20);
    
    S2J_SET_BASIC_ELEMENT(jobj, ifp, string, name);
    if(ifp->alias[0])
        S2J_SET_BASIC_ELEMENT(jobj, ifp, string, alias);

    S2J_SET_BASIC_ELEMENT(jobj,ifp,int,vrf_id);

    if (if_is_up(ifp))
    {
        S2J_SET_STRING(jobj, STATE_KEY, "up");
        if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION)) {
            if (if_is_running(ifp))
                S2J_SET_STRING(jobj, PSTATE_KEY, "up");
            else
    	        S2J_SET_STRING(jobj, PSTATE_KEY, "down");
        } 
    }
    else
        S2J_SET_STRING(jobj, STATE_KEY, "down");

    S2J_SET_STRING(jobj, FLAGS_KEY,if_flag_dump(ifp->flags));
    for(ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc))
    {
        struct prefix *p = ifc->address;
        struct in_addr mask;
        if(ifc->label)
            continue;
        if(p->family != AF_INET)
            continue;
        
        S2J_SET_STRING(jobj, IP_KEY, inet_ntoa(p->u.prefix4));

        masklen2ip(p->prefixlen, &mask);
        S2J_SET_STRING(jobj, MASK_KEY, inet_ntoa(mask));
        
    }
    if(zif&&zif->gw){
        S2J_SET_STRING(jobj, GATEWAY_KEY, inet_ntoa(zif->gw->u.prefix4));
        if(zif->isdefault)
            S2J_SET_STRING(jobj, "default_gw", "1");
    }

    S2J_SET_STRING(jobj, MAC_KEY, mac_str);
    S2J_SET_BASIC_ELEMENT(jobj, ifp, int, mtu);
    S2J_SET_BASIC_ELEMENT(jobj, ifp, int, mtu6);
    S2J_SET_BASIC_ELEMENT(jobj, ifp, int, bandwidth);
    if(ifp->desc)
        S2J_SET_BASIC_ELEMENT(jobj, ifp, string, desc);
    
    if (ifp->flags&IFF_MASTER && zif->bond)
    {
        struct interface *slave;
        
        json_object_object_add(jobj, MODE_KEY, json_object_new_int(zif->bond->bond_mode));
        S2J_SET_STRING(jobj, MODESTR_KEY, bond_mode_tbl[zif->bond->bond_mode]);
        
        struct json_object *arr = json_object_new_array();
        for(ALL_LIST_ELEMENTS_RO(zif->slaves,node,slave))
        {
            json_object_array_add(arr, json_object_new_string(slave->name));
        }
        json_object_object_add(jobj, MEMBERS_KEY, arr);
        
    }
    return JSON_FORMAT_STR(jobj);
}

DEFUN(wml_show_interface,
    wml_show_interface_cmd,
    "show wml interface IFNAME",
    SHOW_STR
    "WWW module interface\n"
    "Interface status and configuration\n"
    "Interface name\n")
{
    struct interface *ifp = if_lookup_by_name(argv[0]);

    if (RUN_AS_INNER() && strstr(self->string, "outer"))
    {
        return vty_adapter_run( vty, vty->usr_data);
    }
    
    if(!ifp)
        return CMD_SUCCESS;
    
    struct json_object *jobj = json_object_new_object();
    vty_out(vty, "%s%s", json_format_interface(ifp, jobj), VTY_NEWLINE);

    json_object_put(jobj);

    return CMD_SUCCESS;
}

DEFUN(wml_show_interface_all,
    wml_show_interface_all_cmd,
    "show wml interface all",
    SHOW_STR
    "WWW module interface\n"
    "Interface status and configuration\n"
    "ALl\n")
{
    struct interface *ifp;
    struct listnode *node;

    if (RUN_AS_INNER() && strstr(self->string, "outer"))
    {
        return vty_adapter_run( vty, vty->usr_data);
    }
    struct json_object *jobj = json_object_new_array();
    struct json_object *j;
    vrf_iter_t iter;

    for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    for(ALL_LIST_ELEMENTS_RO(vrf_iter2iflist(iter), node, ifp))
    {
        if(ifp->alias[0] == '\0')
            continue;
        j = json_object_new_object();
        json_format_interface(ifp, j);
        json_object_array_add(jobj, j);
    }
    
    vty_out(vty, "%s%s", JSON_FORMAT_STR(jobj), VTY_NEWLINE);

    json_object_put(jobj);

    return CMD_SUCCESS;
}

ALIAS(wml_show_interface,
    wml_show_outer_interface_cmd,
    "show wml outer interface IFNAME",
    SHOW_STR
    "WWW module interface\n"
    "Outer side\n"
    "Interface status and configuration\n"
    "Interface name\n");

ALIAS(wml_show_interface_all,
    wml_show_outer_interface_all_cmd,
    "show wml outer interface all",
    SHOW_STR
    "WWW module interface\n"
    "Interface status and configuration\n"
    "ALl\n")
    
const char *json_format_vip(struct interface *ifp, struct json_object *jobj)
{
    struct listnode *node;
    struct connected *ifc;
    
    struct json_object *vip_arr = json_object_new_array();
    json_object_object_add(jobj, NAME_KEY, json_object_new_string(ifp->name));
    json_object_object_add(jobj, ALIAS_KEY, json_object_new_string(ifp->alias));
    for(ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc))
    {
        struct prefix *p = ifc->address;
        struct in_addr mask;
        struct json_object *vobj = json_object_new_object();
        if(!ifc->label)
            continue;
        if(p->family != AF_INET)
            continue;
        
        json_object_object_add(vobj, IP_KEY,  json_object_new_string(inet_ntoa(p->u.prefix4)));

        masklen2ip(p->prefixlen, &mask);
        json_object_object_add(vobj, MASK_KEY, json_object_new_string(inet_ntoa(mask)));

        json_object_object_add(vobj, LABEL_KEY,json_object_new_string(&ifc->label[strlen(ifp->name)+1]));

        json_object_array_add(vip_arr, vobj);
        
    }

    json_object_object_add(jobj, VIPS_KEY, vip_arr);

    return JSON_FORMAT_STR(jobj); 
}

DEFUN(wml_show_vip,
    wml_show_vip_cmd,
    "show wml vip IFNAME",
    SHOW_STR
    "WWW module interface\n"
    "virtual ip address\n"
    "Interface name\n")
{
    struct interface *ifp = if_lookup_by_name(argv[0]);

    if (RUN_AS_INNER() && strstr(self->string, "outer"))
    {
        return vty_adapter_run( vty, vty->usr_data);
    }
    
    if(!ifp)
        return CMD_SUCCESS;
    
    struct json_object *jobj = json_object_new_object();
    vty_out(vty, "%s%s", json_format_vip(ifp, jobj), VTY_NEWLINE);

    json_object_put(jobj);

    return CMD_SUCCESS;
}

DEFUN(wml_show_vip_all,
    wml_show_vip_all_cmd,
    "show wml vip all",
    SHOW_STR
    "WWW module interface\n"
    "virtual ip address\n"
    "Interface name\n")
{
    struct interface *ifp;
    struct listnode *node;

    if (RUN_AS_INNER() && strstr(self->string, "outer"))
    {
        return vty_adapter_run( vty, vty->usr_data);
    }
    struct json_object *jobj = json_object_new_array();
    struct json_object *j;
    for(ALL_LIST_ELEMENTS_RO(vrf_iflist (VRF_DEFAULT), node, ifp))
    {
        if(ifp->alias[0] == '\0')
            continue;
        j = json_object_new_object();
        json_format_vip(ifp, j);
        json_object_array_add(jobj, j);
    }
    
    vty_out(vty, "%s%s", JSON_FORMAT_STR(jobj), VTY_NEWLINE);

    json_object_put(jobj);

    return CMD_SUCCESS;
}

ALIAS(wml_show_vip,
    wml_show_outer_vip_cmd,
    "show wml outer vip IFNAME",
    SHOW_STR
    "WWW module interface\n"
    "Outer side\n"
    "virtual ip address\n"
    "Interface name\n")

ALIAS(wml_show_vip_all,
    wml_show_outer_vip_all_cmd,
    "show wml outer vip all",
    SHOW_STR
    "WWW module interface\n"
    "virtual ip address\n"
    "Interface name\n")

void wml_interface_init()
{
    install_element(VIEW_NODE, &wml_show_interface_cmd);
    install_element(VIEW_NODE, &wml_show_interface_all_cmd);
    install_element(VIEW_NODE, &wml_show_outer_interface_cmd);
    install_element(VIEW_NODE, &wml_show_outer_interface_all_cmd);
    install_element(ENABLE_NODE, &wml_show_interface_cmd);
    install_element(ENABLE_NODE, &wml_show_interface_all_cmd);
    install_element(ENABLE_NODE, &wml_show_outer_interface_cmd);
    install_element(ENABLE_NODE, &wml_show_outer_interface_all_cmd);
    install_element(VIEW_NODE, &wml_show_vip_cmd);
    install_element(VIEW_NODE, &wml_show_vip_all_cmd);
    install_element(VIEW_NODE, &wml_show_outer_vip_cmd);
    install_element(VIEW_NODE, &wml_show_outer_vip_all_cmd);
    install_element(ENABLE_NODE, &wml_show_vip_cmd);
    install_element(ENABLE_NODE, &wml_show_vip_all_cmd);
    install_element(ENABLE_NODE, &wml_show_outer_vip_cmd);
    install_element(ENABLE_NODE, &wml_show_outer_vip_all_cmd);
}
