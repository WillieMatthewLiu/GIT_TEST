#pragma once

extern struct packet_filter g_filter_tcp;
extern struct packet_filter g_filter_tcp_inner;

#include "pktfilter.h"

int buffer_sendtofwd(struct filter_header *hdr, const void *buff, size_t lentgh);
int evbuffer_sendtofwd(struct filter_header *hdr, struct evbuffer *evbf, size_t length); // length=0,表示发送evbf里面的所有数据

int buffer_sendtoreq(struct filter_header *hdr, const void *buff, size_t len);
int evbuffer_sendtoreq(struct filter_header *hdr, struct evbuffer *evbf, size_t length); // length=0,表示发送evbf里面的所有数据

