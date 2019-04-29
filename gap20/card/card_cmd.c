#include "app_common.h"
#include "card_config.h"
#include "command.h"
#include "thread.h"
#include "vty.h"

#include "card_ssl_client.h"
#include "card_crypt.h"
#include "card_route.h"
#include "card_common.h"

//extern char *card_intf[];
extern char card_intf[2][32];
extern struct jobmgr *g_jobmgr;
extern int config_py1(struct Win2cardParam *param);

static struct cmd_node app_node = 
{
    APP_NODE,
    "%s(app)#",
    1,
    NULL,
    NULL
};

const char cSep = ':';
unsigned char* ConverMacAddressStringIntoByte
	(const char *pszMACAddress, unsigned char* pbyAddress)
{
	for (int iConunter = 0; iConunter < 6; ++iConunter)
	{
		unsigned int iNumber = 0;
		char ch;

		//Convert letter into lower case.
		ch = tolower (*pszMACAddress++);

		if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
		{
			return NULL;
		}

		//Convert into number. 
		//       a. If character is digit then ch - '0'
		//	b. else (ch - 'a' + 10) it is done 
		//	because addition of 10 takes correct value.
		iNumber = isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);
		ch = tolower (*pszMACAddress);

		if ((iConunter < 5 && ch != cSep) || 
			(iConunter == 5 && ch != '\0' && !isspace (ch)))
		{
			++pszMACAddress;

			if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
			{
				return NULL;
			}

			iNumber <<= 4;
			iNumber += isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);
			ch = *pszMACAddress;

			if (iConunter < 5 && ch != cSep)
			{
				return NULL;
			}
		}
		/* Store result.  */
		pbyAddress[iConunter] = (unsigned char) iNumber;
		/* Skip cSep.  */
		++pszMACAddress;
	}
	return pbyAddress;
}

DEFUN (_app_card_enter, 
        app_card_enter_cmd,
        "app",
        "Enter card configuration\n"
        )
{
    vty->node = APP_NODE;
    return CMD_SUCCESS;
}

DEFUN (show_card_conf,
       show_card_conf_cmd,
       "show card conf",
       SHOW_STR
       "card\n"
       "interface configure\n")
{
	struct in_addr phy1ip, mask, gateway, gapip;
	
	phy1ip.s_addr = g_jobmgr->param.phy1ip;
	mask.s_addr = g_jobmgr->param.mask;
	gateway.s_addr = g_jobmgr->param.gateway;
	gapip.s_addr = g_jobmgr->param.gapip;
	
	vty_out(vty, "HWaddr: %02x:%02x:%02x:%02x:%02x:%02x  inet addr: %s%s", g_jobmgr->param.mac[0], g_jobmgr->param.mac[1], 
		                                                                                         g_jobmgr->param.mac[2], g_jobmgr->param.mac[3],
		                                                                                         g_jobmgr->param.mac[4], g_jobmgr->param.mac[5], 
		                                                                                         inet_ntoa(phy1ip), VTY_NEWLINE);
	
	vty_out(vty,"Mask: %s  ", inet_ntoa(mask));
	vty_out(vty,"Gateway: %s  ", inet_ntoa(gateway));
	vty_out(vty,"Gapip: %s%s", inet_ntoa(gapip), VTY_NEWLINE);
	
	return CMD_SUCCESS;
}

DEFUN (show_tcp_info,
       show_tcp_info_cmd,
       "show tcp info",
       SHOW_STR
       "tcp\n"
       "tcp connection information\n")
{
	vty_out(vty, "connection number: %d%s", g_jobmgr->conncnt, VTY_NEWLINE);
	vty_out(vty, "send packets: %d, reveived packets: %d%s", g_jobmgr->sendpkts, g_jobmgr->rcvpkts, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (show_ssl_session,
       show_ssl_session_cmd,
       "show ssl session",
       SHOW_STR
       "ssl\n"
       "session state\n")
{
	vty_out(vty, "ssl state: %s%s", g_jobmgr->gap_active?"connect":"disconnect", VTY_NEWLINE);
	vty_out(vty, "ca certificates      : %s%s", g_jobmgr->ssl_cfg.ca_cert, VTY_NEWLINE);
	vty_out(vty, "private certificates : %s%s", g_jobmgr->ssl_cfg.my_cert, VTY_NEWLINE);
	//vty_out(vty, "private key          : %s%s", g_jobmgr->ssl_cfg.my_key, VTY_NEWLINE);
	
	return CMD_SUCCESS;
}

DEFUN (show_routes,
       show_routes_cmd,
       "show routes",
       SHOW_STR
       "Displays the routes string\n")
{
	vty_out(vty, "%s%s", g_jobmgr->routestr, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (set_card_mac,
       set_card_mac_cmd,
       "set card mac LINE",
       "set card mac address\n"
       "card\n"
       "mac\n"
       "address\n")
{
	//printf("\r\n%s\r\n", argv[0]);
	if(ConverMacAddressStringIntoByte(argv[0], g_jobmgr->param.mac) == NULL)
	{
		return CMD_ERR_NO_MATCH;
	}
	
	return CMD_SUCCESS;
}

DEFUN (set_card_ip,
       set_card_ip_cmd,
       "set card ip A.B.C.D",
       SET_STR
       "card\n"
       "ip\n" 
       "address\n")
{
	//printf("\r\n%s\r\n", argv[0]);
	g_jobmgr->param.phy1ip = inet_addr(argv[0]);
	return CMD_SUCCESS;
}

DEFUN (set_card_netmask,
       set_card_netmask_cmd,
       "set card netmask A.B.C.D",
       SET_STR
       "card\n"
       "netmask\n"
       "mask value\n")
{
	//printf("\r\n%s\r\n", argv[0]);
	g_jobmgr->param.mask = inet_addr(argv[0]);
	return CMD_SUCCESS;
}

DEFUN (set_card_gw,
       set_card_gw_cmd,
       "set card gw A.B.C.D",
       SET_STR
       "card\n"
       "gateway\n"
       "address\n")
{
	//printf("\r\n%s\r\n", argv[0]);
	g_jobmgr->param.gateway = inet_addr(argv[0]);
	return CMD_SUCCESS;
}

DEFUN (set_card_gapip,
       set_card_gapip_cmd,
       "set card gapip A.B.C.D",
       SET_STR
       "card\n"
       "gapip\n"
       "address\n")
{
	//printf("\r\n%s\r\n", argv[0]);
	g_jobmgr->param.gapip = inet_addr(argv[0]);
	if(config_py1(&g_jobmgr->param) < 0)
		return -1;
	return CMD_SUCCESS;
}

DEFUN (add_route_tbl,
       add_route_tbl_cmd,
       "add route ip A.B.C.D maskbits <1-32>",
       "add\n"
       "route\n"
       "ip\n"
       "address\n"
       "maskbits\n"
       "number\n")
{
	unsigned int ip; 
	int mask_bits;

	ip = inet_addr(argv[0]);
	mask_bits = atoi(argv[1]);
	add_route(g_jobmgr->routes, ntohl(ip), mask_bits);
	
	return CMD_SUCCESS;
}

DEFUN (add_routes_tbl,
       add_routes_tbl_cmd,
       "add routes .LINE",
       "add\n"
       "routes\n"
       "string\n")
{
       char *routestr = NULL;
       
	if(!strcmp(argv[0], "null"))
	{
		clear_routes(g_jobmgr->routes);
		return CMD_SUCCESS;
	}
	
	if(g_jobmgr->routestr)
		SCFree(g_jobmgr->routestr);
	
	routestr = strstr(vty->buf, argv[0]);
	g_jobmgr->routestr = SCMalloc(strlen(routestr));
	if(g_jobmgr->routestr == NULL)
	{
		SCLogError( "g_jobmgr->routestr alloc error!");
		return CMD_ERR_NOTHING_TODO;
	}
	
	memset(g_jobmgr->routestr, 0, strlen(routestr));
	g_jobmgr->routestr_len = strlen(routestr)-1;
	memcpy(g_jobmgr->routestr, routestr, g_jobmgr->routestr_len);

	add_routes(g_jobmgr->routes, g_jobmgr->routestr, g_jobmgr->routestr_len, card_intf[0]);
	
	return CMD_SUCCESS;
}

int app_config_write(struct vty *vty)
{
	int write = 0;
	struct in_addr phy1ip, mask, gateway, gapip;

       vty_out(vty, "app%s", VTY_NEWLINE);
       write++;

	phy1ip.s_addr = g_jobmgr->param.phy1ip;
	mask.s_addr = g_jobmgr->param.mask;
	gateway.s_addr = g_jobmgr->param.gateway;
	gapip.s_addr = g_jobmgr->param.gapip;

	vty_out(vty, "set card mac %02x:%02x:%02x:%02x:%02x:%02x%s", g_jobmgr->param.mac[0], 
		                                                                                        g_jobmgr->param.mac[1], g_jobmgr->param.mac[2], 
		                                                                                        g_jobmgr->param.mac[3],g_jobmgr->param.mac[4], 
		                                                                                        g_jobmgr->param.mac[5], VTY_NEWLINE);
	vty_out(vty, "set card ip %s%s", inet_ntoa(phy1ip), VTY_NEWLINE);
	vty_out(vty, "set card netmask %s%s", inet_ntoa(mask), VTY_NEWLINE);
	vty_out(vty, "set card gw %s%s", inet_ntoa(gateway), VTY_NEWLINE);
	vty_out(vty, "set card gapip %s%s", inet_ntoa(gapip), VTY_NEWLINE);
	write += 5;
	
	if(g_jobmgr->routestr)
	{
		vty_out(vty,"add routes %s%s", g_jobmgr->routestr, VTY_NEWLINE);
	}
	else
	{
		vty_out(vty,"add routes null%s", VTY_NEWLINE);
	}
	write++;

	return write;
}

int card_cmd_init()
{
	install_node(&app_node, app_config_write);
	install_default(APP_NODE);

	install_element (CONFIG_NODE, &app_card_enter_cmd);
	install_element(APP_NODE, &set_card_mac_cmd);
	install_element(APP_NODE, &set_card_ip_cmd);
	install_element(APP_NODE, &set_card_netmask_cmd);
	install_element(APP_NODE, &set_card_gw_cmd);
	install_element(APP_NODE, &set_card_gapip_cmd);
	install_element(APP_NODE, &add_route_tbl_cmd);
	install_element(APP_NODE, &add_routes_tbl_cmd);
	//install_element(APP_NODE, &set_card_id_cmd);

	install_element(APP_NODE, &show_card_conf_cmd);
	install_element(APP_NODE, &show_tcp_info_cmd);
	install_element(APP_NODE, &show_ssl_session_cmd);
	install_element(APP_NODE, &show_routes_cmd);
	install_element(ENABLE_NODE, &show_card_conf_cmd);
	install_element(ENABLE_NODE, &show_tcp_info_cmd);
	install_element(ENABLE_NODE, &show_ssl_session_cmd);
	install_element(ENABLE_NODE, &show_routes_cmd);
       
	return 0;
}



