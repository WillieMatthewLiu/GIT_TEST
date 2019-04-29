#pragma once

#include "tlvtypes.h"
#include "app_common.h"

struct tlvhdr {
	int type;
	int length;
	uint8_t value[0];
};

struct tlvbox {
	struct evbuffer *buff;
	struct evbuffer *buff_tmp;
	void* fastfind[TLV_TYPE_COUNT];
};

struct tlvbox* tlvbox_create(size_t presize);
struct tlvbox* tlvbox_attach(void *buff, size_t size);
struct tlvbox* tlvbox_load(void *buff, size_t size);
void tlvbox_clear(struct tlvbox *box);
int tlvbox_free(struct tlvbox *box);

size_t tlvbox_get_size(struct tlvbox *box);
int tlvbox_to_buff(struct tlvbox *box, void *buff, size_t len);
void* tlvbox_raw_buff(struct tlvbox *box);
int tlvbox_to_fd(struct tlvbox *box, evutil_socket_t fd);
int tlvbox_dump(struct tlvbox *box, int hexlen);

int tlvbox_put_uint8(struct tlvbox *box, int type, uint8_t value);
int tlvbox_put_uint16(struct tlvbox *box, int type, uint16_t value);
int tlvbox_put_uint32(struct tlvbox *box, int type, uint32_t value);
int tlvbox_put_uint64(struct tlvbox *box, int type, uint64_t value);
int tlvbox_put_string(struct tlvbox *box, int type, char *value);
int tlvbox_put_string_fmt(struct tlvbox *box, int type, char *fmt, ...);
int tlvbox_put_bytes(struct tlvbox *box, int type, void *value, size_t length);
int tlvbox_put_bytes_ref(struct tlvbox *box, int type, void *value, size_t length, evbuffer_ref_cleanup_cb cleanupfn, void *cleanupfn_arg);
int tlvbox_put_bytes_evbf(struct tlvbox *box, int type, struct evbuffer *evbf, size_t length);

struct tlvhdr* tlvbox_find(struct tlvbox *box, int type);
struct tlvhdr* tlvbox_findnext(struct tlvbox *box, int type, struct tlvhdr *curr);

size_t tlv_get_size(struct tlvhdr *hd);
uint8_t tlv_get_uint8(struct tlvhdr *hd);
uint16_t tlv_get_uint16(struct tlvhdr *hd);
uint32_t tlv_get_uint32(struct tlvhdr *hd);
uint64_t tlv_get_uint64(struct tlvhdr *hd);
void* tlv_get_bytes(struct tlvhdr *hd);
char* tlv_get_string(struct tlvhdr *hd);
