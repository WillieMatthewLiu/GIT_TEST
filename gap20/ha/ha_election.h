#ifndef _HA_ELECTION_H_
#define _HA_ELECTION_H_

#include <arpa/inet.h>
#include <netinet/in.h>

#define HA_FLAG_FORCE_ACT (1<<0)
#define HA_FLAG_FORCE_STB (1<<1)

int HaElectionInit();
int HaElectionRequest(HaState nHaState, uint8_t nPriority, uint16_t nFlags, HaHost* pHaHost, HaFaultNotifyMsg* pFaultNotifyMsg);

#endif