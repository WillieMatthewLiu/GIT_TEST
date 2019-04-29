#ifndef _CARD_COMMON_H_
#define _CARD_COMMON_H_
#include "config.h"
#define ICMP_PARAM_TAG "ACORN_ICMP:"

#define SSL_SESSION_EXPIRE_TIME_VAL  (60*5)  // 5 min
#define SSL_HEARTBEAT_TIME_VAL (10) //10s
#define SSL_RECONNECT_TIME_VAL (60*5) // 5 min

#define SSL_CONNECT_MAX_ERR_TIMES (2)

#define ETH_HEAD_LEN  (14)
#define IPV6_HEAD_LEN (40)
#define TCP_FLAGS_SYN  (0x2)
#define TCP_FLAGS_SYN_ACK (0x12)

enum TCP_HANDSHAKE_STATE
{
	TCP_IDLE,
	TCP_SYN,
	TCP_ACK_SYN,
	TCP_ACK
};

struct Win2cardParam {
	unsigned int phy1ip;
	unsigned int mask;
	unsigned int gateway;
	unsigned char mac[6];
	unsigned char rev[2];
	/*
	*gap ip
	*/
	unsigned int gapip;
}__attribute__ ((aligned (4)));

typedef int		Bool;
struct jobmgr {
	struct event_base* base ;
	struct event *ssl_free_timer;
	struct event *ssl_hb_timer; /* heartbeat timer */
	struct event *ssl_reconnect_timer; /* heartbeat timer */
	struct event *eth0timer;
	
	struct event *ev_rcv_win;
	struct event *ev_rcv_wire;

	unsigned char *eth0_buf;
	unsigned char *eth1_buf;

	struct Win2cardParam param;
	HashListTable *routes[32];
	char *routestr;
	int routestr_len;
	
	ssl_session * session;
	pthread_mutex_t ssl_mutex;
	Bool gap_active;
	open_ssl_cfg 	ssl_cfg;
	
	struct TcpPayloadKey tcpkey;
	unsigned int conncnt; //tcp connection count
	unsigned int sendpkts, rcvpkts;
	//unsigned int oldsendpkts, oldrcvpkts;
	int handshake_state;
	
	pthread_t ph1thread;
	pthread_t ph2thread;
	
	pthread_t evthread;
	int ready;

};

unsigned char* ConverMacAddressStringIntoByte
	(const char *pszMACAddress, unsigned char* pbyAddress);

int card_cmd_init();

#endif
