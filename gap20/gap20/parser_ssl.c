
#include "app_common.h"

#include "pktfilter.h"
#include "parser_ssl.h"
#include "usertable.h"
#include "gapconfig.h"

#include "nlkernel.h"
#include "nlkernelmsg.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

SSL_CTX *g_ctx = NULL;

struct sslsession
{
	int ssl_handok;
	SSL *ssl_ptr;
	uint32_t uid;
};

struct sslsession* sslsession_new()
{
	struct sslsession *ret = SCMalloc(sizeof(struct sslsession));
	memset(ret, 0, sizeof(*ret));
	ret->ssl_ptr = SSL_new(g_ctx);
	SSL_set_bio(ret->ssl_ptr, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
	return ret;
}

void sslsession_free(struct sslsession *session)
{
	if (session->uid > 0)
	{
		struct gap_user *usr = usertable_getbyid(session->uid, 0);
		if (usr != NULL)
		{
			struct nl_kernel_msg msg;
			msg.type = NLCMD_UKEY;
			msg.op = NLOP_REMOVE;
			msg.data.ukey.uid = usr->id;
			memcpy(msg.data.ukey.key, (char*)usr->key, 32);
			nlkernel_sendmsg(&msg);

			usertable_free_user(usr);
		}
	}

	SSL_free(session->ssl_ptr);
	SCFree(session);
}

void ssl_do_flush(struct filter_header *hdr, SSL *ssl)
{
	int n = 0;
	char buff[10240];
	while ((n = BIO_read(SSL_get_wbio(ssl), buff, sizeof(buff))) > 0)
		hdr->respcb(hdr, buff, n);
}

int ssl_appendenc(struct filter_header *hdr, SSL *ssl, const void *buff, size_t len)
{
	return BIO_write(SSL_get_rbio(ssl), buff, (int)len);
}

int ssl_dohand(struct filter_header *hdr, SSL *ssl)
{
	int ret = SSL_accept(ssl);
	ssl_do_flush(hdr, ssl);
	if (ret < 0)
	{
		if (SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ)
			return -1;
		return 0;
	}
	return ret;
}

int ssl_doshutdown(struct filter_header *hdr, SSL *ssl)
{
	int ret = SSL_shutdown(ssl);
	ssl_do_flush(hdr, ssl);
	if (ret < 0)
	{
		if (SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ)
			return -1;
		return 0;
	}
	return ret;
}

int ssl_recvplain(struct filter_header *hdr, SSL *ssl, void *buff, size_t len)
{
	int cnt = 0;

	hdr = hdr;
	while (1)
	{
		int ret = SSL_read(ssl, (char*)buff + cnt, (int)len);
		if (ret <= 0)
		{
			if (SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ)
				return -1;
			return cnt;
		}
		cnt += ret;
		len -= ret;
	}
	return 0;
}

void ssl_sendplain(struct filter_header *hdr, struct sslsession *session, const void *buff, size_t len)
{
	SSL_write(session->ssl_ptr, buff, (int)len);
	ssl_do_flush(hdr, session->ssl_ptr);
}

uint32_t update_client_info(const void *buff, size_t len, X509 *clicert)
{
	assert(len == 4 + 16 + 16);	// 4:USERID   16:iv   16:key

	uint32_t uid = *((uint32_t*)buff);
	uid = ntohl(uid);

	char name[1024] = { 0 };
	{
		char *subject = X509_NAME_oneline(X509_get_subject_name(clicert), NULL, 0);
		char *issuer = X509_NAME_oneline(X509_get_issuer_name(clicert), NULL, 0);
		if (subject)
		{
			char *p = strstr(subject, "/CN=") + 4;
			if (p != (void*)4)
				strncpy(name, p, sizeof(name));
		}
		OPENSSL_free(subject);
		OPENSSL_free(issuer);
	}
	if (name[0] == 0)
		return 0;

	if (uid == 0)
		uid = usertable_generic_id();

	struct gap_user *user = usertable_getbyid(uid, 1);
	if (user->name)
		SCFree(user->name);
	user->name = SCStrdup(name);
	memcpy(user->key, (char*)buff + 4, sizeof(user->key));

	struct nl_kernel_msg msg;
	msg.type = NLCMD_UKEY;
	msg.op = NLOP_ADD;
	msg.data.ukey.uid = uid;
	memcpy(msg.data.ukey.key, (char*)buff + 4, 32);
	nlkernel_sendmsg(&msg);

	return user->id;
}

enum FLT_RET ssl_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	int ret;

	if (ev == FLTEV_ONCLIIN)
	{
		struct sslsession *session = sslsession_new();
		hdr->user = session;
		return FLTRET_OK;
	}

	if (ev == FLTEV_ONSOCKDATA)
	{
		struct sslsession *session = hdr->user;
		if (session == NULL)
			return FLTRET_CLOSE;
		ret = ssl_appendenc(hdr, session->ssl_ptr, buff, len);

		// SSL握手
		if (session->ssl_handok == 0)
		{
			ret = ssl_dohand(hdr, session->ssl_ptr);
			if (ret == -1)
			{
				SCLogInfo("on ssl, ssl_dohand ret: %d", ret);
				return ssl_ondata(hdr, FLTEV_ONSOCKERROR, NULL, 0);
			}
			session->ssl_handok = ret;
			return FLTRET_OK;
		}

		// SSL解密数据
		char sslbuff[10240] = { 0 };
		ret = ssl_recvplain(hdr, session->ssl_ptr, sslbuff, sizeof(sslbuff));
		if (ret == -1)
		{
			SCLogInfo("on ssl, ssl_recvplain ret: %d", ret);
			return ssl_ondata(hdr, FLTEV_ONSOCKERROR, NULL, 0);
		}
		buff = sslbuff; len = ret;

		// 数据不足，忽略
		if (ret == 0)
			return FLTRET_OK;

		// 长度不对，关闭
		if (ret != 4 + 16 + 16)
		{
			//SCLogInfo("on ssl, recv data, invalid length: %d", ret);
			char *err = "invalid data";
			ssl_sendplain(hdr, session, err, strlen(err));
			return FLTRET_OK;
		}

		if (session->uid == 0)
		{
			// 收到了加密卡送过来的密钥  4:ID   16:iv   16:key
			X509 *cert = SSL_get_peer_certificate(session->ssl_ptr);
			session->uid = update_client_info(buff, len, cert);
			X509_free(cert);
		}
		SCLogInfo("on ssl, uid: %d, len: %d", session->uid, (int)len);

		// 把UID发给加密卡
		uint32_t uid = htonl(session->uid);
		ssl_sendplain(hdr, session, &uid, sizeof(uid));

		return FLTRET_OK;
	}

	if (ev == FLTEV_ONSOCKERROR)
	{
		SCLogInfo("on ssl, socket closed");
		struct sslsession *session = hdr->user;
		if (session == NULL)
			return FLTRET_CLOSE;
		sslsession_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}

	assert(0);
	return FLTRET_OK;
}

#define CRYPTO_NUM_LOCKS                41
pthread_mutex_t g_ssllock[CRYPTO_NUM_LOCKS];
void lockingcb(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&g_ssllock[type]);
	else
		pthread_mutex_unlock(&g_ssllock[type]);
}

unsigned long idcb(void)
{
	return (unsigned long)pthread_self();
}

#include <openssl/engine.h>

static ENGINE *try_load_engine(BIO *err, const char *engine)
{
	ENGINE *e = ENGINE_by_id("dynamic");
	if (e) {
		if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
			|| !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
			ENGINE_free(e);
			e = NULL;
		}
	}
	return e;
}

ENGINE *setup_engine(BIO *err, const char *engine)
{
	ENGINE *e = NULL;

	ENGINE_load_builtin_engines();
	if (engine) {
		if ((e = ENGINE_by_id(engine)) == NULL
			&& (e = try_load_engine(err, engine)) == NULL) {
			BIO_printf(err, "invalid engine \"%s\"\n", engine);
			ERR_print_errors(err);
			return NULL;
		}
		if (!ENGINE_init(e)) {
			/* the engine couldn't initialise, release 'e' */
			ENGINE_free(e);
			return NULL;
		}
		if (!ENGINE_set_default(e, ENGINE_METHOD_RSA)) {
			BIO_printf(err, "can't use that engine\n");
			ERR_print_errors(err);
			ENGINE_free(e);
			return NULL;
		}

		BIO_printf(err, "engine \"%s\" set.\n", ENGINE_get_id(e));
		ENGINE_finish(e);
		/* Free our "structural" reference. */
		ENGINE_free(e);
	}

	return e;
}

BIO *bio_err = NULL;
BIO *bio_stdout = NULL;

const char *engine = "is8u256a_rsa";
int verify_depth = 0;
int verify_quiet = 0;
int verify_error = X509_V_OK;
int verify_return_error = 0;

static void nodes_print(BIO *out, const char *name,
	STACK_OF(X509_POLICY_NODE) *nodes)
{
	X509_POLICY_NODE *node;
	int i;
	BIO_printf(out, "%s Policies:", name);
	if (nodes) {
		BIO_puts(out, "\n");
		/*for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
			node = sk_X509_POLICY_NODE_value(nodes, i);
			X509_POLICY_NODE_print(out, node, 2);
		}*/
	}
	else
		BIO_puts(out, " <empty>\n");
}

void policies_print(BIO *out, X509_STORE_CTX *ctx)
{
	X509_POLICY_TREE *tree;
	int explicit_policy;
	int free_out = 0;
	if (out == NULL) {
		out = BIO_new_fp(stderr, BIO_NOCLOSE);
		free_out = 1;
	}
	tree = X509_STORE_CTX_get0_policy_tree(ctx);
	explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

	BIO_printf(out, "Require explicit Policy: %s\n",
		explicit_policy ? "True" : "False");

	nodes_print(out, "Authority", X509_policy_tree_get0_policies(tree));
	nodes_print(out, "User", X509_policy_tree_get0_user_policies(tree));
	if (free_out)
		BIO_free(out);
}

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
	X509 *err_cert;
	int err, depth;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	if (!verify_quiet || !ok) {
		BIO_printf(bio_err, "depth=%d ", depth);
		if (err_cert) {
			X509_NAME_print_ex(bio_err,
				X509_get_subject_name(err_cert),
				0, XN_FLAG_ONELINE);
			BIO_puts(bio_err, "\n");
		}
		else
			BIO_puts(bio_err, "<no cert>\n");
	}
	if (!ok) {
		BIO_printf(bio_err, "verify error:num=%d:%s\n", err,
			X509_verify_cert_error_string(err));
		if (verify_depth >= depth) {
			if (!verify_return_error)
				ok = 1;
			verify_error = X509_V_OK;
		}
		else {
			ok = 0;
			verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
		}
	}
	switch (err) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		BIO_puts(bio_err, "issuer= ");
		X509_NAME_print_ex(bio_err, X509_get_issuer_name(err_cert),
			0, XN_FLAG_ONELINE);
		BIO_puts(bio_err, "\n");
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		BIO_printf(bio_err, "notBefore=");
		ASN1_TIME_print(bio_err, X509_get_notBefore(err_cert));
		BIO_printf(bio_err, "\n");
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		BIO_printf(bio_err, "notAfter=");
		ASN1_TIME_print(bio_err, X509_get_notAfter(err_cert));
		BIO_printf(bio_err, "\n");
		break;
	case X509_V_ERR_NO_EXPLICIT_POLICY:
		if (!verify_quiet)
			policies_print(bio_err, ctx);
		break;
	}
	if (err == X509_V_OK && ok == 2 && !verify_quiet)
		policies_print(bio_err, ctx);
	if (ok && !verify_quiet)
		BIO_printf(bio_err, "verify return:%d\n", ok);
	return (ok);
}

SSL_CTX* sslengine_getctx()
{
	int ret;
	ENGINE *e = NULL;
	SSL_CTX *ctx;
	EVP_PKEY *pkey = NULL;
	const char* pRsg_id = "id1";

	printf("%s(%d) openssl server\n", __FUNCTION__, __LINE__);

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	//setup_engine(bio_err, engine);

	ctx = SSL_CTX_new(TLSv1_2_method());
	if (ctx == NULL) {
		printf("%s(%d) create ctx failed\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	ret = SSL_CTX_use_certificate_file(ctx, g_gapcfg->ssl_svrcrt, SSL_FILETYPE_PEM);
	if (ret <= 0) {
		BIO_printf(bio_err, "error setting certificate\n");
		ERR_print_errors(bio_err);
		return NULL;
	}

	e = ENGINE_by_id(engine);
	if (e) {
		pkey = ENGINE_load_public_key(e, pRsg_id, NULL, NULL);
		if (pkey == NULL) {
			printf("%s(%d) set public key failed\n", __FUNCTION__, __LINE__);
			return NULL;
		}
	}
	if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
		BIO_printf(bio_err, "error use private key\n");
		ERR_print_errors(bio_err);
		return NULL;
	}

	/*
	* Now we know that a key and cert have been set against the SSL context
	*/
	if (!SSL_CTX_check_private_key(ctx)) {
		BIO_printf(bio_err, "Public key does not match the certificate\n");
		return NULL;
	}

	if (!SSL_CTX_load_verify_locations(ctx, g_gapcfg->ssl_svrcacrt, NULL)) {
		ERR_print_errors(bio_err);
	}

	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(g_gapcfg->ssl_svrcacrt));

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	return ctx;
}


int ssl_soft_oninit()
{
	int ret;

	do
	{
		for (int i = 0; i < CRYPTO_NUM_LOCKS; i++)
			pthread_mutex_init(&g_ssllock[i], NULL);
		CRYPTO_set_locking_callback(lockingcb);
		CRYPTO_set_id_callback(idcb);

		SSL_load_error_strings();

		ret = SSL_library_init();
		g_ctx = SSL_CTX_new(SSLv23_method());
		if (g_ctx == NULL)
			break;

		SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, NULL);

		ret = SSL_CTX_load_verify_locations(g_ctx, g_gapcfg->ssl_svrcacrt, NULL);
		if (ret != 1)
		{
			SCLogError("ssl: load server_ca cert failed");
			ret = -1;
			break;
		}
		ret = SSL_CTX_use_certificate_file(g_ctx, g_gapcfg->ssl_svrcrt, SSL_FILETYPE_PEM);
		if (ret != 1)
		{
			SCLogError("ssl: load server cert failed");
			ret = -1;
			break;
		}
		ret = SSL_CTX_use_PrivateKey_file(g_ctx, g_gapcfg->ssl_svrkey, SSL_FILETYPE_PEM);
		if (ret != 1)
		{
			SCLogError("ssl: load server key failed");
			ret = -1;
			break;
		}

		ret = SSL_CTX_check_private_key(g_ctx);
		if (ret != 1)
		{
			ret = -1;
			break;
		}

		ret = usertable_init();
		if (ret != 0)
			break;

	} while (0);

	if (ret != 0)
	{
		int ssl_onfree();
		ssl_onfree();
		ret = -1;
	}
	return ret;
}

int ssl_oninit()
{
	int ret;

	do
	{
		//CRYPTO_malloc_init();
		CRYPTO_set_mem_functions(malloc, realloc, free);

		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		ENGINE_load_builtin_engines();

		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
		bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

		g_ctx = sslengine_getctx();
		if (g_ctx == NULL)
		{
#define KEY_PATH "/etc/openssl/private/gap.key"
			struct stat info;
			if (stat(KEY_PATH, &info) == 0)
			{
				ret = system("load_rsa_key prikey "KEY_PATH);
				if (ret == 0)
					unlink(KEY_PATH);
			}
			break;
		}

		for (int i = 0; i < CRYPTO_NUM_LOCKS; i++)
			pthread_mutex_init(&g_ssllock[i], NULL);
		CRYPTO_set_locking_callback(lockingcb);
		CRYPTO_set_id_callback(idcb);

		ret = usertable_init();
		if (ret != 0)
			break;

	} while (0);

	if (ret != 0)
	{
		return ssl_soft_oninit();
	}
	return ret;
}

int ssl_onfree()
{
	if (g_ctx != NULL)
		SSL_CTX_free(g_ctx);
	for (int i = 0; i < CRYPTO_NUM_LOCKS; i++)
		pthread_mutex_destroy(&g_ssllock[i]);
	usertable_free();

	return 0;
}

static struct packet_filter g_filter_ssl = { SVR_ID_SSL, "ssl session", ssl_oninit, ssl_ondata, ssl_onfree };

PROTOCOL_FILTER_OP(ssl)

