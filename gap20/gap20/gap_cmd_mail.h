/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : gap_cmd_mail.h
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.6.14
Description    : mail vty
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#ifndef __GAP_CMD_MAIL_H__
#define __GAP_CMD_MAIL_H__
#include "app_common.h"

/* valid */
#define MAIL_CONFIG_VALID           "valid"

/* attachment */
#define MAIL_CONFIG_ATTACH          "attachments"
#define MAIL_CONFIG_SIZE            "size"
#define MAIL_CONFIG_SUFFIXS         "suffixs"

/* address */
#define MAIL_CONFIG_ADDRESS         "address"
#define MAIL_CONFIG_ACCOUNTS        "accounts"

/* content */
#define MAIL_CONFIG_CONTENT         "content"
#define MAIL_CONFIG_KEYWORDS        "keywords"

/* mail config command init */
void mail_conf_cmd_init(void);

/* mail cmd init */
void mail_cmd_init(void);

/* mail cmd exit */
void mail_cmd_exit(void);

#endif
