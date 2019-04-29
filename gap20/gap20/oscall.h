#pragma once

int os_exec(const char *cmd);
int os_exec_rd(const char *cmd, char **response);
void os_sleep(int msec);
int os_gettick();

uint64_t os_longlonginc(uint64_t *p, uint64_t n);
uint64_t os_longlongdec(uint64_t *p, uint64_t n);

// add nat rule to system
int addnat(const char *sip, uint16_t sport, const char *dip, uint16_t dport, int protocol);

// remove nat rule from system
int delnat(const char *sip, uint16_t sport, const char *dip, uint16_t dport);

// get mac from system arp table
int getarp(char *ifname, char *ip, void *mac);

// ipv4 to string, net order
int addr2str(u_int ip, char *ret);

// string to mac
void imac_addr(char *str, uint8_t *mac);

// parse string
int parsestring(char *str, ...);

