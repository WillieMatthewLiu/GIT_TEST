#include <semaphore.h>
#include "zebra.h"
#include "app_common.h"
#include "util-debug.h"
#include "card_config.h"
#include "thread.h"
#include "command.h"
#include "card_ssl_client.h"

#define USE_EXTERN_SSL_ENGIN

open_ssl_cfg * g_ssl_cfg = NULL;

#ifdef USE_EXTERN_SSL_ENGIN
BIO *bio_err = NULL;
BIO *bio_stdout = NULL;

const char *engine = "is8u256a_rsa";
EVP_PKEY *pkey = NULL;
#else
const char *app_ciper_type_str[SSL_CIPER_TYPE_MAX] = {"RC4-MD5", "AES256-SHA"};
#endif

int free_ssl_ctx(ssl_session_ctx *ctx)
{

	/* close the connection session */	
	if(ctx->ssl != NULL)
	{
		SSL_shutdown (ctx->ssl);
		SSL_free (ctx->ssl);
		ctx->ssl = NULL;
	}
	if(ctx->ctx != NULL)
	{
		SSL_CTX_free (ctx->ctx);
		ctx->ctx = NULL;
	}

	ctx->meth = NULL;
	
	return 0;
}

ssl_session * alloc_ssl_session()
{
	ssl_session * session = SCMalloc(sizeof(ssl_session));
	
	if(session == NULL)
	{
		SCLogError( "ssl sesseon alloc error!");
		return NULL;
	}
	memset(session, 0, sizeof(ssl_session));
	session->sockfd = -1;

	pthread_mutex_init(&session->ssl_free_lock, NULL);
	
	return session;
}

void free_ssl_session(ssl_session * session)
{
	if(session == NULL)
		return;

	pthread_mutex_lock(&session->ssl_free_lock);
	free_ssl_ctx(&session->ctx);
	if(session->sockfd > 0)
	{
		close(session->sockfd);
		session->sockfd = -1;
	}
	pthread_mutex_unlock(&session->ssl_free_lock);
	
	session->connected = 0;
}

#ifdef USE_EXTERN_SSL_ENGIN
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
		if(!ENGINE_init(e)) {
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

void init_ssl_lib(void)
{
	int i, ret;
	int 	seed_int[100];
	ENGINE *e = NULL;
	const char *ked_id = "id1";

    struct stat info;
    SCLogInfo( "load private key\n");
    if(stat(SSL_DEFAULT_MYKEYF, &info) == 0)
	{
		ret = system("load_rsa_key prikey "SSL_DEFAULT_MYKEYF);
		if (ret == 0)
		{
		    SCLogInfo("load private key OK\n");
			unlink(SSL_DEFAULT_MYKEYF);
		}
	}

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	setup_engine(bio_err, engine);

	e = ENGINE_by_id(engine);
	if(e) 
    {
		pkey = ENGINE_load_public_key(e, ked_id, NULL ,NULL);
		if (pkey == NULL) {
			SCLogError( "load public key failed\n");
			return;
		}
	}
	
	/* according to system time, generate one random number */
	srand ((unsigned) time (NULL));
	for (i = 0; i < 100; i++)
	{
		seed_int[i] = rand ();
	}
	RAND_seed (seed_int, sizeof (seed_int));
    
}

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
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(out, node, 2);
        }
    } else
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
        } else
            BIO_puts(bio_err, "<no cert>\n");
    }
    if (!ok) {
        BIO_printf(bio_err, "verify error:num=%d:%s\n", err,
                   X509_verify_cert_error_string(err));
        if (verify_depth >= depth) {
            if (!verify_return_error)
                ok = 1;
            verify_error = X509_V_OK;
        } else {
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


int init_ssl_ctx(ssl_session_ctx *ctx, int sockfd)
{
	ctx->meth = (SSL_METHOD *) TLSv1_2_method();

	ctx->ctx = SSL_CTX_new (ctx->meth);
	if (NULL == ctx->ctx)
	{
		SCLogError( "SSL context create failure !!!");
		return -1;
	}

	if (0 == SSL_CTX_use_certificate_file (ctx->ctx, g_ssl_cfg->my_cert, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp (stderr);
		return -1;
	}

	if(!SSL_CTX_load_verify_locations(ctx->ctx, g_ssl_cfg->ca_cert, NULL))
	{
		ERR_print_errors(bio_err);
	}

	if(SSL_CTX_use_PrivateKey(ctx->ctx, pkey) <= 0) {
		BIO_printf(bio_err, "error use private key\n");
		ERR_print_errors(bio_err);
		return 0;
	}

	SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_PEER, verify_callback);

	SSL_CTX_set_mode (ctx->ctx, SSL_MODE_AUTO_RETRY);

	ctx->ssl = SSL_new (ctx->ctx);

	if (NULL == ctx->ssl)
	{
		SCLogError( "SSL_new failed.");
		return -1;
	}

	if (0 >= SSL_set_fd (ctx->ssl, sockfd))
	{
		SCLogError( "SSL attach to Line failure!");
		return -1;
	}

	return 0;
	
}

int init_ssl_client_session(ssl_session *session)
{
	int err;
	X509 *peer;
	char buf[1024] = {0};
    struct timeval timeout={2,0};

	if((session->sockfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
	{
		SCLogError( "Creating socket failed.");
		return -1;
	}
	SCLogInfo("to connect tcp\n");
	setsockopt(session->sockfd,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout));
	if (connect(session->sockfd, (struct sockaddr *) &session->gap_addr, sizeof (session->gap_addr)) < 0)
	{
		SCLogError( "can not connect to server: %s:%d, error string: %s", 
				inet_ntoa(session->gap_addr.sin_addr), ntohs(session->gap_addr.sin_port), strerror (errno));
		closesocket(session->sockfd);
		session->sockfd = -1;
        return -1;
	}
	SCLogInfo("tcp connect ok\n");

	if(init_ssl_ctx(&session->ctx, session->sockfd) < 0)
	{
		SCLogError( "init_ssl_session failed.");
		close(session->sockfd);
		session->sockfd = -1;
		return -1;
	}

	if ((err = SSL_connect(session->ctx.ssl)) == 0)
	{
		ERR_print_errors_fp(stderr);
		SCLogError( "SSL_connect failed!");
		close(session->sockfd);
		session->sockfd = -1;
		free_ssl_ctx(&session->ctx);
		return -1;
	}

	peer = SSL_get_peer_certificate(session->ctx.ssl);
	if (peer != NULL) {
		BIO_printf(bio_err, "Server certificate\n");
		PEM_write_bio_X509(bio_err, peer);
		X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
		BIO_printf(bio_err, "subject=%s\n", buf);
		X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
		BIO_printf(bio_err, "issuer=%s\n", buf);
		X509_free(peer);
	}

	session->connected = 1;
	return 0;
}

#else

void init_ssl_lib(void)
{
	int i;
	int 	seed_int[100];


	/* SSL library initial */
	SSL_library_init();
	/* load all SSL algorithms */
	OpenSSL_add_ssl_algorithms ();
	/* load all SSL error message */
	SSL_load_error_strings ();

	/* according to system time, generate one random number */
	srand ((unsigned) time (NULL));
	for (i = 0; i < 100; i++)
	{
		seed_int[i] = rand ();
	}
	RAND_seed (seed_int, sizeof (seed_int));
    
}

int init_ssl_ctx(ssl_session_ctx *ctx, int sockfd)
{
	ctx->meth = (SSL_METHOD *) SSLv23_method();

	ctx->ctx = SSL_CTX_new (ctx->meth);
	if (NULL == ctx->ctx)
	{
		SCLogError("SSL context create failure !!!");
		return -1;
	}

	SSL_CTX_set_verify (ctx->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations (ctx->ctx, g_ssl_cfg->ca_cert, NULL);
	if (0 == SSL_CTX_use_certificate_file (ctx->ctx, g_ssl_cfg->my_cert, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp (stderr);
		return -1;
	}
	//if (0 == _SSL_CTX_use_PrivateKey_file (ctx->ctx, SSL_DEFAULT_MYKEYF, SSL_FILETYPE_PEM))
	if (0 == SSL_CTX_use_PrivateKey_file(ctx->ctx, g_ssl_cfg->my_key, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp (stderr);
		return -1;
	}
	if (!SSL_CTX_check_private_key (ctx->ctx))
	{
		SCLogError("Private key does not match the certificate public key");
		return -1;
	}

	/*cllient mode*/
	SSL_CTX_set_cipher_list (ctx->ctx, app_ciper_type_str[g_ssl_cfg->ciper]);

	
	SSL_CTX_set_mode (ctx->ctx, SSL_MODE_AUTO_RETRY);

	ctx->ssl = SSL_new (ctx->ctx);
	if (NULL == ctx->ssl)
	{
		SCLogError("SSL_new failed.");
		return -1;
	}

	if (0 >= SSL_set_fd (ctx->ssl, sockfd))
	{
		SCLogError("SSL attach to Line failure!");
		return -1;
	}

	return 0;
	
}

int init_ssl_client_session(ssl_session *session)
{
	int err;
    struct timeval timeout={2,0};

	if((session->sockfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
	{
		SCLogError( "Creating socket failed.");
		return -1;
	}
	SCLogInfo("to connect tcp\n");
	setsockopt(session->sockfd,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout));
	if (connect(session->sockfd, (struct sockaddr *) &session->gap_addr, sizeof (session->gap_addr)) < 0)
	{
		SCLogError("can not connect to server: %s:%d, error string: %s", 
				inet_ntoa(session->gap_addr.sin_addr), ntohs(session->gap_addr.sin_port), strerror (errno));
		closesocket(session->sockfd);
		session->sockfd = -1;
        return -1;
	}
	SCLogInfo("tcp connect ok\n");

	if(init_ssl_ctx(&session->ctx, session->sockfd) < 0)
	{
		SCLogError("init_ssl_session failed.");
		close(session->sockfd);
		session->sockfd = -1;
		return -1;
	}

	if ((err = SSL_connect(session->ctx.ssl)) == 0)
	{
		ERR_print_errors_fp(stderr);
		SCLogError("SSL_connect failed!");
		close(session->sockfd);
		session->sockfd = -1;
		free_ssl_ctx(&session->ctx);
		return -1;
	}

	session->connected = 1;
	return 0;
}
#endif

void init_ssl_cfg_as_default(open_ssl_cfg * ssl_cfg)
{
	g_ssl_cfg = ssl_cfg;
	strncpy(ssl_cfg->ca_cert, SSL_DEFAULT_CACERT, APP_MAX_FILE_NAME);
	strncpy(ssl_cfg->my_cert, SSL_DEFAULT_MYCERTF, APP_MAX_FILE_NAME);
    
#ifndef USE_EXTERN_SSL_ENGIN
	strncpy(ssl_cfg->my_key, SSL_DEFAULT_MYKEYF, APP_MAX_FILE_NAME);
	ssl_cfg->ciper = SSL_CIPER_TYPE_AES256_SHA;
#endif
}

