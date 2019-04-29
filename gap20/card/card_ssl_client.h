#ifndef _CARD_SSL_CLIENT_H_
#define _CARD_SSL_CLIENT_H_

#include <openssl/bio.h> 
#include <openssl/engine.h> 
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_DEFAULT_PORT 9001
#define SSL_DEFAULT_CACERT 		"/etc/openssl/private/ca.crt"
#define SSL_DEFAULT_MYCERTF 	"/etc/openssl/certs/gap.crt"
#define SSL_DEFAULT_MYKEYF 		"/etc/openssl/private/gap.key"

typedef struct _ssl_session_ctx {
	SSL 		*ssl;
	SSL_METHOD	*meth;
	SSL_CTX 	*ctx;
       	
}ssl_session_ctx;

typedef struct _ssl_session {
	int sockfd;
	struct sockaddr_in gap_addr;
	int connected; // 0: ssl disconnect 1: ssl connected
	int connect_failed_times;
	time_t connect_time;
	ssl_session_ctx ctx;
	pthread_mutex_t ssl_free_lock;
 	pthread_t pthread;
	sem_t sem_id;
}ssl_session;

ssl_session * alloc_ssl_session();
int init_ssl_client_session(ssl_session *session);
void free_ssl_session(ssl_session * session);
void init_ssl_lib(void);
void init_ssl_cfg_as_default(open_ssl_cfg * ssl_cfg);

#endif

