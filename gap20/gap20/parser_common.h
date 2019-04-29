/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_common.h
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.2.8
Description    : common header file
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#ifndef __PARSER_COMMON_H__
#define __PARSER_COMMON_H__
#include "app_common.h"
#include "appsession.h"

/****************************** Macro ******************************/
/* Description */
#define GAP_DESC(X)             1

/* Invalid value definition */
#define PARSER_INVALUE8         (0xFFU)
#define PARSER_INVALUE16        (0xFFFFU)
#define PARSER_INVALUE32        (0xFFFFFFFFU)

/* Bool */
#define PARSER_BTRUE            ~0
#define PARSER_BFALSE           0

/* Unit conversion */
#define PARSER_BYTE_PER_KB      1024
#define PARSER_KB_PER_MB        1024
#define PARSER_MB_PER_GB        1024

/* Common buff size */
#define PARSER_COMMON_LEN       32

/* IP address cache size */
#define PARSER_IP_BUFF_SIZE     16
#define PARSER_PORT_BUFF_SIZE   6

/* Ip number to string */
#define IP_NUM_TO_STR(ipNum, ipStr, ipStrLen) \
    do \
    { \
        snprintf((char *)ipStr, (int)ipStrLen, "%u.%u.%u.%u", \
                 ((unsigned char *)&ipNum)[0], ((unsigned char *)&ipNum)[1], \
                 ((unsigned char *)&ipNum)[2], ((unsigned char *)&ipNum)[3]); \
    } while (0)

/* Get auto id by hdr */
#define GET_AUTO_ID_BY_HDR(hdr, autoId) \
    do \
    { \
        struct app_session *s = OFFSET_OBJECT(hdr, app_session, flthdr); \
        *autoId = s->auto_id; \
    } while (0)

/* Get parent id by hdr */
#define GET_PARENT_ID_BY_HDR(hdr, parentId) \
    do \
    { \
        struct app_session *s = OFFSET_OBJECT(hdr, app_session, flthdr); \
        *parentId = s->parent_id; \
    } while (0)


/****************************** Struct *****************************/


/****************************** Enum *******************************/
/* Return */
typedef enum PARSER_RETURN_E
{
	PARSER_ERROR = -1,
	PARSER_OK,
	PARSER_CONTINUE,
	PARSER_USED,
	PARSER_BUSY
} PARSER_RETURN;


/*********************** External variables ************************/
extern int g_runouter;      /**< 0:not outer 1:outer */
extern int g_runinner;      /**< 0:not inner 1:inner */


/****************************** Function ***************************/
/* String repalce */
int strreplace(char *data, char *srcStr, char *dstStr);

/* Memory match */
unsigned char *memnmem(unsigned char *dst, unsigned short dstLen, unsigned char *src, unsigned short srcLen);

/* Find src in the first len character of dst */
char *strnstr(char *dst, char *src, int len);

/* Wide char to char */
int wide2Char(char *inbuf, unsigned int inlen, char *outbuf, unsigned int outlen);

/* Char to wide char */
int char2Wide(char *inbuf, unsigned int inlen, char *outbuf, unsigned int outlen);

/* utf8 to gb2312 */
int utf8togb2312(const char *sourcebuf, size_t sourcelen, char *destbuf, size_t destlen);

/* gb2312 to utf8 */
int gb2312toutf8(const char *sourcebuf, size_t sourcelen, char *destbuf, size_t destlen);

#endif

