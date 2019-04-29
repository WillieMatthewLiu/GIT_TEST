#ifndef _APP_CONFIG_H_
#define _APP_CONFIG_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>



#define APP_DEFAULT_CERT_FILES_PATH		APP_DEFAULT_INSTALL_PATH "/" APP_DEFAULT_CERT_DIR_NAME

#define APP_DEFAULT_FIFO_NAME 		APP_DEFAULT_INSTALL_PATH "/ssl_fifo"
//#define APP_DEFAULT_FIFO_PATHNAME 		APP_DEFAULT_INSTALL_PATH "/" APP_DEFAULT_FIFO_NAME

#define APP_DEFAULT_CONFIG_FILE_NAME    "config.ini"
#define APP_DEFAULT_CONFIG_FILE     APP_DEFAULT_INSTALL_PATH "/" APP_DEFAULT_CONFIG_FILE_NAME

#define APP_CONFIG              "/etc/app.conf"

#define APP_MAX_SSL_SESSION 100

typedef struct _app_map{
	char *key;
	char *value;
	struct _app_map *next;
}app_map;


typedef enum
{
	SSL_CIPER_TYPE_RC4_MD5 = 0,
	SSL_CIPER_TYPE_AES256_SHA = 1,
	SSL_CIPER_TYPE_MAX = 2,
}SSL_CIPER_TYPE;

enum ssl_cfg_file_type{
    SSL_CFG_FILE_CA_CERT,
    SSL_CFG_FILE_MY_CERT,
    SSL_CFG_FILE_MY_KEY
};
#define APP_MAX_FILE_NAME 256  // path and file name
typedef struct _open_ssl_cfg
{
	char		ca_cert[APP_MAX_FILE_NAME];  /* root ca */
	char		my_cert[APP_MAX_FILE_NAME];  /* localca */
	char		my_key[APP_MAX_FILE_NAME];

	SSL_CIPER_TYPE ciper;
	
}open_ssl_cfg;






#endif // _APP_CONFIG_H_
