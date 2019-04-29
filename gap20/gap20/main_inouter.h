#ifndef _MAIN_INOUTER_H_
#define _MAIN_INOUTER_H_

#include "zebra.h"
#include "if.h"
#include "prefix.h"

#define GAPVER_STANDARD 1
#define GAPVER_GUANGTIE 1001
extern int g_pciready;


int inner_outer_run();

struct filter_header* sessionmap_gethdr_fromid(uint32_t sessionid);
int sessionmap_postclose_byhdr(struct filter_header *hdr);
int get_sockfd_byhdr(struct filter_header *hdr);

int vty_onservice_onoff(int enable);
extern int vtyhlp_closeall_byaddr(struct interface *ifp, const char *localip);
extern int vtyhlp_applyroute(struct route_item *route);
#endif
