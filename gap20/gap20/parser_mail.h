/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_mail.h
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.5.31
Description    : mail process
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#ifndef __PARSER_MAIL_H__
#define __PARSER_MAIL_H__

/* MAIL code length */
#define MAIL_CODE_LEN                   256

/* MAIL common length */
#define MAIL_COMMON_LEN                 64

/* IP address cache size */
#define MAIL_IP_BUFF_SIZE               16

/* MAIL application cache size */
#define MAIL_BUFF_DATA_LEN              1536

/* MAIL head length */
#define MAIL_HEAD_LEN                   4

/* MAIL end flag of body length */
#define MAIL_END_BODY_LEN               4

/* MAIL wrap length */
#define MAIL_ONE_WRAP_LEN               2
#define MAIL_TWO_WRAP_LEN               4

/* MAIL smtp end flag length */
#define MAIL_SMTP_END_LEN               3

/* MAIL pop3 end flag length */
#define MAIL_POP3_END_LEN               5

/* MAIL null of content end flag length */
#define MAIL_NO_CONTENT_END_LEN         6

/* MAIL attachment path */
#define MAIL_ATTACHMENT_PATH_LEN        64

/* MAIL default size */
#define MAIL_DEFAULT_SIZE               (20 * PARSER_KB_PER_MB * PARSER_BYTE_PER_KB)

/* MAIL attachment path */
#define MAIL_ATTACHMENT_PATH            "/var/volatile/tmp/attachment/"

/* Session connection status */
typedef enum MAIL_CONNECT_STATUS_E
{
	MAIL_DISCONNECT = 0,
	MAIL_CONNECTING,
	MAIL_CONNECTED
} MAIL_CONNECT_STATUS;

/* Data processing rule */
typedef enum MAIL_DATA_RULE_E
{
	MAIL_DATA_NORMAL = 0,
	MAIL_DATA_DROP,
	MAIL_DATA_CLOSE
} MAIL_DATA_RULE;

/* Mail type */
typedef enum MAIL_TYPE_E
{
	MAIL_SMTP = 0,
	MAIL_POP3
} MAIL_TYPE;

/* Data processing rule */
typedef enum MAIL_KEY_E
{
	MAIL_EHLO = 0,
	MAIL_AUTH,
	MAIL_USER,
	MAIL_PASS,
	MAIL_STAT,
	MAIL_LIST,
	MAIL_UIDL,
	MAIL_RETR,
	MAIL_FROM,
	MAIL_TO,
	MAIL_DATA,
	MAIL_QUIT,
	MAIL_SIZE,
	MAIL_SUBJECT,
	MAIL_ENCODING,
	MAIL_FILENAME,
	MAIL_POP3_OK,
	MAIL_POP3_FROM,
	MAIL_POP3_TO,
	MAIL_POP3_CC,

	MAIL_KEY_BUTT
} MAIL_KEY;

/* Session information */
typedef struct MAIL_SESSION_S
{
	int isValid;
	int reserve;
	int connecting;
	int isStartMail;
	int isCheckSubject;
	int isCheckContent;
	int mailSize;
	int analySize;
	FILE *fp;
	char *contentEncode;
	char *attachmentEncode;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} MAIL_SESSION;

/* Mail key of header */
typedef struct MAIL_KEY_INFO_S
{
	int len;
	char *key;
} MAIL_KEY_INFO;

/* Independment Configure struct */
typedef struct MAIL_INDEPENDENT_CONFIG_S
{
	char dataRule;
	char isSaveAttachment;
} MAIL_INDEPENDENT_CONFIG;

/* Rule queue */
typedef struct MAIL_RULE_QUEUE_S
{
	struct list_head list;
	char name[MAIL_COMMON_LEN];
} MAIL_RULE_QUEUE;

/* Attachment config */
typedef struct MAIL_ATTACH_CONFIG_S
{
	int mailSize;       /*<< BYTES */
	int suffixCount;
	char **suffixs;
} MAIL_ATTACH_CONFIG;

/* Account config */
typedef struct MAIL_ACCOUNT_CONFIG_S
{
	int accountCount;
	char **accounts;
} MAIL_ACCOUNT_CONFIG;

/* Content config */
typedef struct MAIL_CONTENT_CONFIG_S
{
	int keywordCount;
	char **keywords;
} MAIL_CONTENT_CONFIG;

/* Configure struct */
typedef struct MAIL_CONFIG_S
{
	int valid;
	int reserve;
	char *mailJsonStr;
	MAIL_ATTACH_CONFIG  attachConfig;
	MAIL_ACCOUNT_CONFIG accountConfig;
	MAIL_CONTENT_CONFIG contentConfig;
} MAIL_CONFIG;

extern MAIL_KEY_INFO g_mailKeyInfo[MAIL_KEY_BUTT];

int smtp_isSaveAttachment(void);
int pop3_isSaveAttachment(void);
void mail_removeOldFile(char *filePath, MAIL_TYPE mailType);
int mail_writeDataToFile(MAIL_SESSION *session, MAIL_TYPE mailType, char *data, int len);

char *mail_getConfig(void);
void mail_setConfig(MAIL_CONFIG *mailConfig);
void mail_freeObjMemory(MAIL_CONFIG *mailConfig);

/* Check mail size */
int mail_isMailSizeValid(int mailSize);

/* Check suffix */
int mail_isSuffixValid(char *filePath, int isEncode);

/* Check account */
int mail_isAccountValid(char *account);

/* Check content */
int mail_isContentValid(char *content, char *encoding);

/* Get filename full path */
void mail_getFilenameFullPath(char *path, char *fileName, int fileNameLen, int *isEncode);

/* Replace unknow character */
void mail_replaceUnknowChar(char *filePath);

#endif
