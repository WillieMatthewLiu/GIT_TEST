#include <zebra.h>


#include "vty.h"
#include "command.h"
#include "linklist.h"
#include "memory.h"

#include "usermgmt.h"

static struct list *group_list;
static struct list *user_list;

struct login_access_map{
    char *access;
    int mask;
};

static const char *reserve_group[]={
    "root",
    NULL
};

static int is_reserve_group(const char *group)
{
    const char **rg = reserve_group;

    while(*rg){
        if(strcmp(*rg, group) == 0)
            return 1;
        rg++;
    }
    return 0;
}

static const char *reserve_user[] = {
    "root", 
    "admin",
    NULL
};

static int is_reserve_user(const char *user)
{
    const char **ru = reserve_user;

    while(*ru){
        if(strcmp(*ru, user) == 0)
            return 1;
        ru++;
    }
    return 0;
}


static const struct login_access_map _login_access_map[] = {
    {"console", GAP_LOGIN_ACCESS_CONSOLE},
    {"ssh2", GAP_LOGIN_ACCESS_SSH},
    {"web", GAP_LOGIN_ACCESS_WEB},
    {NULL, 0},
};

static int get_login_access_id(const char *access)
{
    const struct login_access_map *login_map= _login_access_map;

    while(login_map->access){
        if(strcmp(access, login_map->access) == 0)
            return login_map->mask;
    }

    return 0;
}

static struct group *sys_addgroup(const char *name)
{
    if(!getgrnam(name)){
        cmd_system_novty_arg("addgroup %s", name);
    }

    return getgrnam(name);
}

static struct group *sys_delgroup(const char *name)
{
    cmd_system_novty_arg("delgroup %s", name);

    return getgrnam(name);
}

DEFUN(add_group,
    add_group_cmd,
    "group GROUPNAME access {console|ssh2|web}",
    "Management group\n"
    "group name\n"
    "Login access\n"
    "Permit login by console\n"
    "Permit login by SSH2\n"
    "Permit login by Web\n"
    "Description\n")
{
    struct listnode *node;
    struct group *group;
    struct gap_mgmt_group *mg;
    const char *name = argv[0];
    int access = 0;


    if(is_reserve_group(name))
    {
        vty_out(vty, "can't add a reserved group name.!%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    group = sys_addgroup(name);
    if(!group)
    {
        vty_out(vty, "add group fail.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if(argv[1]){
        access += get_login_access_id(argv[1]);
    }
    if(argv[2])
        access += get_login_access_id(argv[2]);
    if(argv[3])
        access += get_login_access_id(argv[3]);

    /* check name */
    for(ALL_LIST_ELEMENTS_RO(group_list,node,mg))
    {
        if(strcmp(name, mg->group_name) == 0)
            break;
    }

    if(!mg){
        mg = XCALLOC(MTYPE_TMP, sizeof(struct gap_mgmt_group));
        listnode_add(group_list, mg);
        mg->group_name = XSTRDUP(MTYPE_TMP, name);
    }
    if(access  != mg->access)
        mg->access = access;

    if(!mg->creator)
    {
        mg->creator = XSTRDUP(MTYPE_TMP, vty->username);
        time(&mg->createtime);
    }
    else
    {
        time(&mg->modifytime);
    }

    return CMD_SUCCESS;
}

DEFUN(del_group,
    del_group_cmd,
    "no group GROUPNAME",
    NO_STR
    "Manager Group\n"
    "Group name\n")
{
    const char *name = argv[0];
    struct listnode *node, *nextnode;
    struct gap_mgmt_group *mg;

    if(sys_delgroup(name))
    {
        vty_out(vty, "group %s is used.%s", name, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    for(ALL_LIST_ELEMENTS(group_list,node,nextnode,mg))
    {
        printf("%p %p", node, mg);
        if(strcmp(name, mg->group_name)==0)
        {
            LISTNODE_DETACH(group_list,node);
            break;
        }
    }
    if(mg)
    {
        XFREE(MTYPE_TMP, mg->group_name);
        XFREE(MTYPE_TMP, mg->desc);
        XFREE(MTYPE_TMP, mg->creator);
        XFREE(MTYPE_TMP, mg);
    }

    return CMD_SUCCESS;
}

DEFUN(add_user,
    add_user_cmd,
    "user USERNAME group GROUPNAME",
    "User maitaince\n")
{
    return CMD_SUCCESS;
}
static struct cmd_node user_node={
    SYS_USER_NODE,
    "",
    1,
};

static int user_config_write(struct vty*vty)
{
    int w = 0;
    struct listnode *node;
    struct gap_mgmt_group *mg;

    for(ALL_LIST_ELEMENTS_RO(group_list,node,mg))
    {
        vty_out(vty, "group %s %s", mg->group_name, VTY_NEWLINE);
        w++;
    }
    
        
    return w;
}

void usermgmt_init()
{

    group_list = list_new();
    user_list = list_new();

    install_node(&user_node, user_config_write);
    install_element(CONFIG_NODE, &add_group_cmd);
    install_element(CONFIG_NODE, &del_group_cmd);
}

