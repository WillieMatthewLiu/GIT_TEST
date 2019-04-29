#ifndef _IPT_H_
#define _IPT_H_

enum port_type {
	PORT_TYPE_TCP,
	PORT_TYPE_UDP,
	PORT_TYPE_INVALID
};
typedef enum port_type PortType;

struct port {
	PortType type;
	int port;
	char *ipt_rule;
};

int add_ipt_allowed_port(PortType type, int port_val);
int del_ipt_allowed_port(PortType type, int port_val);
int ipt_init(int hash_size);
void ipt_exit();

#endif
