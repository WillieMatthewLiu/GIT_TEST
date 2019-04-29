#include <zebra.h>
#include <command.h>

#include "app_common.h"

#include "util-lock.h"
#include "util-list.h"
#include "gap_stgy.h"
#include "gap_ctl.h"
#include "tlvbox.h"
#include "forwardcmd.h"
#include "db_mysql.h"

extern int check_privilege(struct acl_data *ad, char proto[], char rule[], int len);
extern int check_ipmac(unsigned int ip, unsigned char *mac, char rule[], int len);

#define GET_VALUE(buffer, key, value, result)\
    if (get_value('=', ';', buffer, key, value,sizeof(value))!= result)\
    {\
        SCLogInfo("Get %s failed.", key);\
        return -1;\
    }

/*
copy  the data between limit1 and limit2 to  result  eg:name=11;pwd=12
@ limit1: the start position
@ limit2: the end position
@ buf: source buf
@ name: the obj's name
@ result: destination data
@ len: the max len of result
@ return: 0:error;1:required options ;2:not required options
*/
static int get_value(char limit1, char limit2,
	char *buf, char *name, char *result, int len)
{
	int i, diff = 0;
	char *start = buf;
	char *end;
	char str[128];
	/* buf is "id=;type=3;name=ffdfd" */
	snprintf(str, sizeof(str), "%s%c", name, limit1);
again:
	start = strstr(start + diff, str);
	if (!start)
		return 0;
	if ((*start != *buf) && (*(start - 1) != limit2) && (*(start - 1) != ' '))
	{
		diff = 1;
		goto again;
	}

	/* find limit1  */
	start = strchr(start, limit1);
	if (!start)
		return 0;

	start += 1;
	/* find limit2  */
	do {
		end = strchr(start, limit2);
		if (end)
			break;
		end = strchr(start, '\0');
		if (!end)
			return 0;
	} while (0);

	if ((i = end - start) >= len)
		return 0;

	/*copy  the data  to  result */
	strncpy(result, start, i);
	result[i] = '\0';
	if (0 == i)
		return 2;

	return 1;
}

void release_acl_data(void *private)
{
	if (private) {
		SCFree(private);
	}
}

int get_acl_data(char *buf, struct acl_data *ad)
{
	char dir[8];
	char src_level[8];
	char dst_level[8];
	unsigned char *mac = ad->smac;

	if (0 == strlen(buf))
		return -1;

	/* dir=1;smac=50:7B:9D:A0:8A:04;sip=192.168.10.139;sport=63110;dip=192.168.44.11;dport=21;uname=none;sif=P0;dif=P0;routename=ftp;routetype=0;guessok=0;srclevel=3;dstlevel=3*/
	memset(ad, 0, sizeof(*ad));

	GET_VALUE(buf, "routename", ad->route, 1);
	GET_VALUE(buf, "sif", ad->inif, 1);
	GET_VALUE(buf, "dif", ad->outif, 1);
	GET_VALUE(buf, "smac", ad->c_smac, 1);
	GET_VALUE(buf, "sip", ad->c_sip, 1);
	GET_VALUE(buf, "sport", ad->c_sport, 1);
	GET_VALUE(buf, "dip", ad->c_dip, 1);
	GET_VALUE(buf, "dport", ad->c_dport, 1);
	GET_VALUE(buf, "uname", ad->user, 1);
	GET_VALUE(buf, "dir", dir, 1);
	GET_VALUE(buf, "srclevel", src_level, 1);
	GET_VALUE(buf, "dstlevel", dst_level, 1);

	imac_addr(ad->c_smac, mac);
	ad->sip = inet_addr(ad->c_sip);
	ad->sport = atoi(ad->c_sport);
	ad->dip = inet_addr(ad->c_dip);
	ad->dport = atoi(ad->c_dport);
	ad->dir = atoi(dir);
	ad->src_level = atoi(src_level);
	ad->dst_level = atoi(dst_level);
	return 0;
}

int stgy_check_rule(void* obj, char rule[], int len)
{
	struct acl_data* ad = (struct acl_data*)obj;
	if (ad == NULL) 
	{
		SCLogInfo("ad is NULL.");
		return -1;
	}

	int svc[] = { SVR_ID_HTTP, SVR_ID_HTTPS, SVR_ID_FTP, SVR_ID_FTPDATA,SVR_ID_TDCS, SVR_ID_OPC, SVR_ID_MSSQL, SVR_ID_MYSQL,
		SVR_ID_IEC104, SVR_ID_SMTP, SVR_ID_POP3, SVR_ID_ORCL, SVR_ID_DB2, SVR_ID_MODBUS, SVR_ID_UDP, SVR_ID_SIP, SVR_ID_TCP, SVR_ID_RTSP };
	int i = 0;
	int found = 0;
	for (i = 0; i < countof(svc); i++) 
	{
		if (svc[i] == ad->svrid) 
		{
			found = 1;
			break;
		}
	}
	if (found == 0)
	{
		return 0;
	}		

	const char *proto = proto_strfromid(ad->svrid);

	/* 校验IPMAC规则 */
	int ret = check_ipmac(ad->sip, ad->smac, rule, len);
	if (ret == -1) 
	{
		SCLogInfo("Call check_ipmac() Access %s failed.", proto);
		return -1;
	}
	else if (ret == -2)
	{
		SCLogInfo("Call check_ipmac() Access %s warning.", proto);
		return 1;
	}

	/*校验用户和用户组规则 */
	ret = check_privilege(ad, proto, rule, len);
	if (ret) 
	{
		SCLogInfo("Call check_privilege() Access %s failed.", proto);
		return -1;
	}

	return 0;
}

