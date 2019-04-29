#include "app_common.h"
#include "util-lock.h"
#include "ipt_ctl.h"
#include "command.h"
#include "lib/memory.h"

#define PERMIT_CHAIN "PERMIT"
#define DEF_HASH_SIZE (128)

#define CHECK_NULL(p)   do { \
    if(*(p) == '\0')  \
        return NULL; \
}while(0)

#define JUMP_WHITESPACE(p) do{ \
    while ((*(p) != '\0') && isspace ((int) *(p)))  \
        (p)++;  \
    CHECK_NULL(p);  \
}while(0)

#define PORT_TYPE(type) (type == PORT_TYPE_TCP ? "tcp" : (type == PORT_TYPE_UDP ? "udp" : "unknown"))

static HashListTable * port_ht = NULL;
static pthread_mutex_t port_lock;

uint32_t hashlist_port_hash(HashListTable *tb, void *ptr, uint16_t aa)
{
	struct port *p = ptr;
	return (uint32_t)(p->port % tb->array_size);
}

char hashlist_port_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct port *port1 = p1;
	struct port *port2 = p2;

	return ((port1->type == port2->type) && (port1->port == port2->port));
}

void hashlist_port_onfree(void *ptr)
{
	struct port *p = ptr;
	XFREE(MTYPE_TMP, p->ipt_rule);
	SCFree(p);
}

HashListTable* port_hash_init(int hash_size)
{
	HashListTable *route = NULL;
	route = HashListTableInit(hash_size, hashlist_port_hash, hashlist_port_compare,
		hashlist_port_onfree);
	return route;
}

static char *__mod_ipt_rule_to_del(char *ipt_rule)
{
	char *pos, *start;
	start = zstrdup(MTYPE_TMP, ipt_rule);
	pos = start;

	do {
		pos = strchr(pos, '-');
		if (pos) {
			pos++;
		}
		else {
			free(start);
			return NULL;
		}
	} while (*pos == 't' || *pos == 'w');

	if (*pos == 'A' || *pos == 'I' || *pos == 'C' || *pos == 'R') {
		*pos = 'D';
	}
	pos++;
	/* Skip white spaces. */
	JUMP_WHITESPACE(pos);

	while ((*pos != '\0') && (!isspace((int)*pos)))
		pos++;
	CHECK_NULL(pos);

	/* Skip white spaces. */
	JUMP_WHITESPACE(pos);

	/* replace number after chain name to space*/
	while (isdigit((int)*pos) && *pos != '\0') {
		*pos = ' ';
		pos++;
	}
	return start;
}

void del_iptables_rule(char* ipt_rule)
{
	char *del_str = __mod_ipt_rule_to_del(ipt_rule);
	cmd_system_novty(del_str);
	SCLogInfo("del_ipt_rule: %s\n", del_str);
	XFREE(MTYPE_TMP, del_str);
}

char * ipt_alloc_rule(char *format, ...)
{
#define DEFEND_RULE_LEN   256
	char buf[DEFEND_RULE_LEN] = { 0 };
	va_list ap;
	char *rule = NULL;

	va_start(ap, format);
	vsnprintf(buf, DEFEND_RULE_LEN, format, ap);
	buf[DEFEND_RULE_LEN - 1] = '\0';
	va_end(ap);

	rule = zstrdup(MTYPE_TMP, buf);
	return rule;
}

int get_rule_number(char *rule_comment)
{
	char cmdbuf[256];
	char output[64] = { 0 };
	snprintf(cmdbuf, 256, "iptables -w -L -v -n --line-numbers | grep %s | awk '{print $1}'", rule_comment);
	cmd_system_getout(cmdbuf, output, 64);
	return atoi(output);
}

int add_ipt_allowed_port(PortType type, int port_val)
{
	struct port *port = NULL;
	struct port temp = { 0 };
	char comment[32] = { 0 };
	int rule_id;

	if (!port_ht)
	{
		port_ht = port_hash_init(DEF_HASH_SIZE);
		if (NULL == port_ht)
		{
			SCLogInfo("alloc port hashtable failed!\n");
			return -1;
		}
		mutex_init(&port_lock);
	}

	mutex_lock(&port_lock);

	temp.type = type;
	temp.port = port_val;
	if (HashListTableLookup(port_ht, &temp, sizeof(&temp)))
	{
		SCLogInfo("%s port %d exist\n", PORT_TYPE(temp.type), temp.port);
		mutex_unlock(&port_lock);
		return 0;
	}

	port = (struct port *)SCMalloc(sizeof(*port));
	if (!port)
	{
		SCLogInfo("alloc port node failed!\n");
		mutex_unlock(&port_lock);
		return -1;
	}

	sprintf(comment, "%d%s", port_val, PORT_TYPE(type));
	port->type = type;
	port->port = port_val;
	port->ipt_rule = ipt_alloc_rule("iptables -w -A %s -p %s --destination-port %d -m comment --comment %s -j ACCEPT",
		PERMIT_CHAIN,
		PORT_TYPE(port->type),
		port_val, comment);
	rule_id = get_rule_number(comment);
	SCLogInfo("rule_id: %d\n", rule_id);
	SCLogInfo("ipt_rule: %s\n", port->ipt_rule);
	if (!rule_id)
		cmd_system_novty(port->ipt_rule);
	HashListTableAdd(port_ht, port, sizeof(port));

	mutex_unlock(&port_lock);
	return 0;
}

int del_ipt_allowed_port(PortType type, int port_val)
{
	struct port temp = { 0 };
	struct port *port = NULL;
	int ret = 0;

	mutex_lock(&port_lock);

	temp.type = type;
	temp.port = port_val;
	port = HashListTableLookup(port_ht, &temp, sizeof(&temp));

	if (port)
	{
		del_iptables_rule(port->ipt_rule);
		if (HashListTableRemove(port_ht, port, sizeof(port)) < 0)
		{
			SCLogInfo("del %s port %d from hashtable failed!\n", PORT_TYPE(type), temp.port);
			ret = -1;
		}
	}
	else
	{
		SCLogInfo("%s port %d not exist\n", PORT_TYPE(type), temp.port);
		ret = -1;
	}

	mutex_unlock(&port_lock);
	return ret;
}

int ipt_init(int hash_size)
{
	if (!port_ht)
	{
		port_ht = port_hash_init(hash_size);
		if (NULL == port_ht)
		{
			SCLogInfo("alloc port hashtable failed!\n");
			return -1;
		}
		mutex_init(&port_lock);
	}
	return 0;
}

void ipt_exit()
{
	if (port_ht)
		HashListTableFree(port_ht);
}

