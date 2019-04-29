
#include "app_common.h"
#include "tlvbox.h"
#include "oscall.h"
#include "main_inouter.h"

inline size_t tlv_get_size(struct tlvhdr *hd)
{
	return hd->length;
}

inline uint8_t tlv_get_uint8(struct tlvhdr *hd)
{
	return hd->value[0];
}

inline uint16_t tlv_get_uint16(struct tlvhdr *hd)
{
	return *((uint16_t*)hd->value);
}

inline uint32_t tlv_get_uint32(struct tlvhdr *hd)
{
	return *((uint32_t*)hd->value);
}

inline uint64_t tlv_get_uint64(struct tlvhdr *hd)
{
	return *((uint64_t*)hd->value);
}

inline void* tlv_get_bytes(struct tlvhdr *hd)
{
	return (void*)hd->value;
}

inline char* tlv_get_string(struct tlvhdr *hd)
{
	return (char*)hd->value;
}

struct tlvbox* tlvbox_create(size_t presize)
{
	struct tlvbox* box  = (struct tlvbox*)SCMalloc(sizeof(struct tlvbox));
	if (box == NULL)
	{
		goto ERR;
	}
		
	//memset(box, 0, sizeof(*box));
	memset(box, 0, sizeof(struct tlvbox));
	
	box->buff = evbuffer_new();
	if (box->buff == NULL)
	{
		goto ERR;
	}
		
	if (presize > 0)
	{
		struct evbuffer_iovec vec;
		if (evbuffer_reserve_space(box->buff, presize, &vec, 1) == -1)
			goto ERR;

		vec.iov_len = 0;
		if (evbuffer_commit_space(box->buff, &vec, 1) == -1)
			goto ERR;
	}

	return box;

ERR:
	tlvbox_free(box);
	return NULL;
}

struct tlvbox* tlvbox_attach(void *buff, size_t size)
{
	struct tlvbox *box = tlvbox_create(0);
	if (box == NULL)
		return NULL;

	if (evbuffer_add_reference(box->buff, buff, size, NULL, NULL) == -1)
	{
		tlvbox_free(box);
		return NULL;
	}
	return box;
}

struct tlvbox* tlvbox_load(void *buff, size_t size)
{
	struct tlvbox *box = tlvbox_create(size);
	if (box == NULL)
		return NULL;

	if (evbuffer_add(box->buff, buff, size) == -1)
	{
		tlvbox_free(box);
		return NULL;
	}
	return box;
}

void tlvbox_clear(struct tlvbox *box)
{
	evbuffer_drain(box->buff, evbuffer_get_length(box->buff));
	memset(box->fastfind, 0, sizeof(box->fastfind));
}

int tlvbox_free(struct tlvbox *box)
{
	if (box == NULL)
		return 0;

	if (box->buff != NULL)
		evbuffer_free(box->buff);
	if (box->buff_tmp != NULL)
		evbuffer_free(box->buff_tmp);
	SCFree(box);
	return 0;
}

static int inline tlvbox_doadd(struct tlvbox *box, struct tlvhdr *hd, void *data)
{
	if (evbuffer_expand(box->buff, sizeof(*hd) + hd->length) != 0)
		return -1;
	evbuffer_add(box->buff, hd, sizeof(*hd));
	evbuffer_add(box->buff, data, hd->length);
	return 0;
}
int tlvbox_put_uint8(struct tlvbox *box, int type, uint8_t value)
{
	struct tlvhdr hd = { type, sizeof(value) };
	return tlvbox_doadd(box, &hd, &value);
}

int tlvbox_put_uint16(struct tlvbox *box, int type, uint16_t value)
{
	struct tlvhdr hd = { type, sizeof(value) };
	return tlvbox_doadd(box, &hd, &value);
}

int tlvbox_put_uint32(struct tlvbox *box, int type, uint32_t value)
{
	struct tlvhdr hd = { type, sizeof(value) };
	return tlvbox_doadd(box, &hd, &value);
}

int tlvbox_put_uint64(struct tlvbox *box, int type, uint64_t value)
{
	struct tlvhdr hd = { type, sizeof(value) };
	return tlvbox_doadd(box, &hd, &value);
}

int tlvbox_put_string(struct tlvbox *box, int type, char *value)
{
	return tlvbox_put_bytes(box, type, value, strlen(value) + 1);
}

int tlvbox_put_bytes(struct tlvbox *box, int type, void *value, size_t length)
{
	struct tlvhdr hd = { type, (int)length };
	return tlvbox_doadd(box, &hd, value);
}

int tlvbox_put_bytes_ref(struct tlvbox *box, int type, void *value, size_t length, evbuffer_ref_cleanup_cb cleanupfn, void *cleanupfn_arg)
{
	struct tlvhdr hd = { type, (int)length };
	evbuffer_add(box->buff, &hd, sizeof(hd));
	evbuffer_add_reference(box->buff, value, length, cleanupfn, cleanupfn_arg);
	return 0;
}

int tlvbox_put_bytes_evbf(struct tlvbox *box, int type, struct evbuffer *evbf, size_t length)
{
	struct tlvhdr hd = { type, (int)length };
	evbuffer_add(box->buff, &hd, sizeof(hd));
	evbuffer_remove_buffer(evbf, box->buff, length);
	return 0;
}

int tlvbox_put_string_fmt(struct tlvbox *box, int type, char *fmt, ...)
{
	int n;
	va_list va;
	struct tlvhdr hd = { type, 0 };
	static char zero = '\0';

	if (box->buff_tmp == NULL)
		box->buff_tmp = evbuffer_new();

	va_start(va, fmt);
	n = evbuffer_add_vprintf(box->buff_tmp, fmt, va);
	va_end(va);

	if (evbuffer_expand(box->buff, sizeof(hd) + n + 1) != 0)
	{
		evbuffer_drain(box->buff_tmp, evbuffer_get_length(box->buff_tmp));
		return -1;
	}

	hd.length = n + 1;
	evbuffer_add(box->buff, &hd, sizeof(hd));
	evbuffer_add_buffer(box->buff, box->buff_tmp);
	evbuffer_add(box->buff, &zero, 1);
	return 0;
}

size_t tlvbox_get_size(struct tlvbox *box)
{
	return evbuffer_get_length(box->buff);
}

int tlvbox_to_buff(struct tlvbox *box, void *buff, size_t len)
{
	if (len < evbuffer_get_length(box->buff))
		return -1;
	len = evbuffer_get_length(box->buff);
	int n = (int)evbuffer_copyout(box->buff, buff, len);
	if (n != len)
		n = n;
	return 0;
}

void* tlvbox_raw_buff(struct tlvbox *box)
{
	return evbuffer_pullup(box->buff, evbuffer_get_length(box->buff));
}

int tlvbox_to_fd(struct tlvbox *box, evutil_socket_t fd)
{
	while (1)
	{
		evbuffer_write_atmost(box->buff, fd, -1);
		if (evbuffer_get_length(box->buff) == 0)
			break;
		os_sleep(1);

		if (g_pciready == 0)
			return -1;
	}
	return 0;
}

int tlvbox_dump(struct tlvbox *box, int hexlen)
{
	int sz, type, tlvlen, vallen, ret;
	struct tlvhdr *hd;
	uint8_t *p;
	int i, n, count;

	sz = (int)evbuffer_get_length(box->buff);
	p = evbuffer_pullup(box->buff, evbuffer_get_length(box->buff));

	ret = 0;
	count = 0;
	while (sz > 0)
	{
		hd = (struct tlvhdr*)p;

		tlvlen = sizeof(*hd) + hd->length;
		p += tlvlen;
		sz -= tlvlen;

		type = hd->type;
		vallen = hd->length;
		if (sz < 0 || type > TLV_TYPE_COUNT || type < 0)
		{
			fprintf(stderr, "error on tlv packet: %d", count++);
			ret = -1;
			break;
		}

		fprintf(stderr, "type: %d(%s), length: %d, value: ", type, tlv_enum_to_str(type), vallen);

		if (hd->value[vallen - 1] == 0 && strlen((char*)hd->value) + 1 == vallen)
			fprintf(stderr, "str(\"%s\") ", tlv_get_string(hd));
		if (vallen == 1)
			fprintf(stderr, "u8(%d) ", tlv_get_uint8(hd));
		else if (vallen == 2)
			fprintf(stderr, "u16(%d) ", tlv_get_uint16(hd));
		else if (vallen == 4)
			fprintf(stderr, "u32(%d) ", tlv_get_uint32(hd));
		else if (vallen == 8)
			fprintf(stderr, "u64(%lld) ", tlv_get_uint64(hd));

		n = vallen > hexlen ? hexlen : vallen;
		if (n > 0)
		{
			fprintf(stderr, "bin(");
			for (i = 0; i < n; i++)
			{
				fprintf(stderr, "%02X", hd->value[i]);
				if (i < n - 1)
					fprintf(stderr, " ");
			}
			if (vallen > hexlen)
				fprintf(stderr, " ...)\n");
			else
				fprintf(stderr, ")\n");
		}
		else
		{
			fprintf(stderr, "(bin)\n");
		}
		count++;
	}
	fprintf(stderr, "count: %d, size: %d\n\n", count, evbuffer_get_length(box->buff));

	return ret;
}


struct tlvhdr* tlvbox_find(struct tlvbox *box, int type)
{
	struct tlvhdr *ret = box->fastfind[type];
	if (ret != NULL)
		return ret;

	ret = tlvbox_findnext(box, type, NULL);
	box->fastfind[type] = ret;
	return ret;
}

struct tlvhdr* tlvbox_findnext(struct tlvbox *box, int type, struct tlvhdr *curr)
{
	size_t len;
	struct tlvhdr *hd;
	uint8_t *p, *end;

	p = evbuffer_pullup(box->buff, evbuffer_get_length(box->buff));
	end = p + evbuffer_get_length(box->buff);

	if (curr != NULL)
		p = (uint8_t*)curr + sizeof(*hd) + curr->length;

	while (p < end)
	{
		hd = (struct tlvhdr*)p;
		if (type == hd->type)
			return hd;

		len = sizeof(*hd) + hd->length;
		p += len;
	}
	return NULL;
}
