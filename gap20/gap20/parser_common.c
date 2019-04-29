/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_common.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.3.9
Description    : common functions
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#include <iconv.h>
#include "app_common.h"
#include "svrid.h"
#include "oscall.h"
#include "memory.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "parser_tcp.h"

/* Return Value definition */
#define COMMON_RETURN_OK               0
#define COMMON_RETURN_ERROR            (-1)

/************************************************************
*Function    : strreplace
*Action      : data     data
			   srcStr   source data
			   dstStr   dest data
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.20
*Instruction : null
************************************************************/
int strreplace(char *data, char *srcStr, char *dstStr)
{
	int len;
	int dataLen;
	int srcStrLen;
	int dstStrLen;
	int buffLen;
	char *buff = NULL;
	char *pdata = NULL;
	char *ptemp = NULL;
	char *pwrite = NULL;

	if ((NULL == data) || (NULL == srcStr) || (NULL == srcStr))
	{
		SCLogError("[ERROR]: invalid para, data(%p), srcStr(%p), dstStr(%p)", data, srcStr, dstStr);
		return COMMON_RETURN_ERROR;
	}

	pdata = data;
	ptemp = strstr(pdata, srcStr);
	if (NULL == ptemp)
	{
		return COMMON_RETURN_OK;
	}

	dataLen = strlen(data);
	srcStrLen = strlen(srcStr);
	dstStrLen = strlen(dstStr);
	if (srcStrLen < dstStrLen)
	{
		buffLen = (dataLen / srcStrLen) * (dstStrLen - srcStrLen) + dataLen;
	}
	else
	{
		buffLen = dataLen - (srcStrLen - dstStrLen);
	}

	buff = (char *)malloc(buffLen + 1);
	if (NULL == buff)
	{
		SCLogError("[ERROR]: malloc memory failed, size(%d)", buffLen + 1);
		return COMMON_RETURN_ERROR;
	}

	pwrite = buff;
	while (ptemp)
	{
		len = (int)(ptemp - pdata);
		strncpy(pwrite, pdata, len);
		pwrite += len;
		strncpy(pwrite, dstStr, dstStrLen);
		pwrite += dstStrLen;

		pdata = ptemp + srcStrLen;
		ptemp = strstr(pdata, srcStr);
	}
	strcpy(pwrite, pdata);

	strcpy(data, buff);

	free(buff);
	return COMMON_RETURN_OK;
}

/************************************************************
*Function    : memnmem
*Action      : memory match
*Input       : null
*Output      : null
*Return      : !NULL            mathc
			   NULL             not match
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
unsigned char *memnmem(unsigned char *dst, unsigned short dstLen, unsigned char *src, unsigned short srcLen)
{
	unsigned char *temp = NULL;

	if (dstLen < srcLen)
	{
		return NULL;
	}

	temp = memchr(dst, *src, dstLen);
	if (NULL == temp)
	{
		return NULL;
	}

	dstLen -= temp - dst;
	dst = temp;
	while (dstLen >= srcLen)
	{
		if (0 == memcmp(dst, src, srcLen))
		{
			return dst;
		}

		dst++;
		dstLen--;
		temp = memchr(dst, *src, dstLen);
		if (NULL == temp)
		{
			return NULL;
		}

		dstLen -= temp - dst;
		dst = temp;
	}

	return NULL;
}

/************************************************************
*Function    : ssh_strnstr
*Action      : Find src in the first len character of dst
*Input       : dst  dest string
			   src  source string
			   len  search len
*Output      : null
*Return      : dst      find
			   NULL     not find
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
char *strnstr(char *dst, char *src, int len)
{
	int srcLen;

	if ((NULL == dst) || (NULL == src))
	{
		return NULL;
	}

	srcLen = strlen(src);
	if (0 == srcLen)
	{
		return (char *)dst;
	}

	while (len >= srcLen)
	{
		if (!memcmp(dst, src, srcLen))
		{
			return (char *)dst;
		}
		dst++;
		len--;
	}

	return NULL;
}

/************************************************************
*Function    : wide2Char
*Action      : Wide char to char
*Input       : inbuf        input data
			   inlen        input data length
*Output      : outbuf       output data
			   outlen       output data length
*Return      : COMMON_RETURN_OK    success
			   COMMON_RETURN_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2017.3.6
*Instruction : null
************************************************************/
int wide2Char(char *inbuf, unsigned int inlen, char *outbuf, unsigned int outlen)
{
	unsigned int rdCnt;
	unsigned int wrCnt;

	if (NULL == outbuf)
	{
		SCLogError("[ERROR]: Invalid para, outbuf(%p)", outbuf);
		return COMMON_RETURN_ERROR;
	}

	if (0 == outlen)
	{
		*outbuf = '\0';
		return COMMON_RETURN_OK;
	}

	if ((NULL == inbuf) || (0 == inlen))
	{
		*outbuf = '\0';
		return COMMON_RETURN_OK;
	}

	rdCnt = 0;
	wrCnt = 0;
	while ('\0' != *inbuf)
	{
		if ((rdCnt + 2) > inlen)
		{
			*outbuf = '\0';
			break;
		}

		if ('\0' != *(inbuf + 1))
		{
			*outbuf = '\0';
			break;
		}

		*outbuf = *inbuf;
		wrCnt++;
		outbuf++;

		if (wrCnt >= outlen)
		{
			*outbuf = '\0';
			break;
		}

		inbuf += 2;
		rdCnt += 2;
	}

	if ('\0' == *inbuf)
	{
		*outbuf = '\0';
	}

	return COMMON_RETURN_OK;
}

/************************************************************
*Function    : char2Wide
*Action      : Char to wide char
*Input       : inbuf        input data
			   inlen        input data length
*Output      : outbuf       output data
			   outlen       output data length
*Return      : COMMON_RETURN_OK    success
			   COMMON_RETURN_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2017.3.6
*Instruction : null
************************************************************/
int char2Wide(char *inbuf, unsigned int inlen, char *outbuf, unsigned int outlen)
{
	unsigned int rdCnt;
	unsigned int wrCnt;

	if (NULL == outbuf)
	{
		SCLogError("[ERROR]: Invalid para, outbuf(%p)", outbuf);
		return COMMON_RETURN_ERROR;
	}

	if (0 == outlen)
	{
		*outbuf = '\0';
		return COMMON_RETURN_OK;
	}

	if ((NULL == inbuf) || (0 == inlen))
	{
		*outbuf = '\0';
		return COMMON_RETURN_OK;
	}

	rdCnt = 0;
	wrCnt = 0;
	while ('\0' != *inbuf)
	{
		if (rdCnt > inlen)
		{
			break;
		}

		*outbuf = *inbuf;
		wrCnt++;
		outbuf++;

		if (wrCnt > outlen)
		{
			break;
		}

		*outbuf = '\0';
		wrCnt++;
		outbuf++;

		inbuf++;
		rdCnt++;
	}

	return 0;
}

int utf8togb2312(const char *sourcebuf, size_t sourcelen, char *destbuf, size_t destlen)
{
	iconv_t cd;
	char **dest = NULL;
	const char **source = NULL;

	cd = iconv_open("gb2312", "utf-8");
	if (0 == cd)
	{
		return -1;
	}

	memset(destbuf, 0, destlen);

	dest = &destbuf;
	source = &sourcebuf;
	if (-1 == iconv(cd, (char **)source, &sourcelen, dest, &destlen))
	{
		return -1;
	}

	iconv_close(cd);
	return 0;
}

int gb2312toutf8(const char *sourcebuf, size_t sourcelen, char *destbuf, size_t destlen)
{
	iconv_t cd;
	char **dest = NULL;
	const char **source = NULL;

	cd = iconv_open("utf-8", "gb2312");
	if (0 == cd)
	{
		return -1;
	}

	memset(destbuf, 0, destlen);

	dest = &destbuf;
	source = &sourcebuf;
	if (-1 == iconv(cd, (char **)source, &sourcelen, dest, &destlen))
	{
		return -1;
	}

	iconv_close(cd);
	return 0;
}
