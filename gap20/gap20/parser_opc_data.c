/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_opc_data.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.2.7
Description    : opcdata protocol process
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#include "app_common.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gap_stgy.h"
#include "gapconfig.h"
#include "parser_tcp.h"
#include "db_mysql.h"
#include "parser_common.h"
#include "parser_opc.h"

/* OPC Interface Tables */
extern OPC_INTERFACE_TABLE g_interfaceTables[INTERFACE_BUTT_ID];

/* Configure data */
static OPCDATA_CONFIG g_opcdataConfig;

/************************************************************
*Function    : opcdata_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static OPCDATA_SESSION *opcdata_allocSession(void)
{
	OPCDATA_SESSION *session = NULL;

	session = SCMalloc(sizeof(OPCDATA_SESSION));
	if (NULL == session)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, (unsigned int)sizeof(OPCDATA_SESSION));
		return NULL;
	}
	memset(session, 0, sizeof(*session));
	session->reqBuf = evbuffer_new();
	if (NULL == session->reqBuf)
	{
		SCLogError("[%s:%d]evbuffer_new failed", __func__, __LINE__);
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->rspBuf = evbuffer_new();
	if (NULL == session->rspBuf)
	{
		SCLogError("[%s:%d]evbuffer_new failed", __func__, __LINE__);
		evbuffer_free(session->reqBuf);
		session->reqBuf = NULL;
		SCFree(session);
		session = NULL;
		return NULL;
	}
	session->connecting = OPC_DISCONNECT;
	session->callId = PARSER_INVALUE32;
	session->opnum = PARSER_INVALUE16;
	session->interfaceId = PARSER_INVALUE16;
	return session;
}

/************************************************************
*Function    : opcdata_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opcdata_freeSession(OPCDATA_SESSION *session)
{
	evbuffer_free(session->rspBuf);
	session->rspBuf = NULL;
	evbuffer_free(session->reqBuf);
	session->reqBuf = NULL;
	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : opcdata_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void opcdata_writeSeceventLog(struct filter_header *hdr, int packLen, char *content)
{
	char sourceIp[OPC_IP_BUFF_LEN];
	char destIp[OPC_IP_BUFF_LEN];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;
	char *groupName = NULL;

	addr2str(hdr->ip->saddr, sourceIp);
	addr2str(hdr->ip->daddr, destIp);
	proto = (char*)server_strfromid(SVR_ID_OPC);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);
	groupName = (hdr->svr && hdr->svr->parent_acldata) ? (hdr->svr->parent_acldata->groupname) : "";

	INSERT_ACCESSAUDIT_LOG(autoId, sourceIp, destIp, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
		aclData->user, "none", l_critical, groupName, "false", packLen, content);
}

/************************************************************
*Function    : opcdata_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET opcdata_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	OPCDATA_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogError("[%s:%d]invalid para, hdr(%p), user(%p), maybe session is closed", __func__, __LINE__, hdr, hdr->user);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		opcdata_writeSeceventLog(hdr, packLen, content);
	}

	session = hdr->user;

	opcdata_freeSession(session);
	hdr->user = NULL;

	SCLogInfo("[%s:%d]on socket close, ssid(%u)", __func__, __LINE__, hdr->sessionid);

	return FLTRET_CLOSE;
}

#if GAP_DESC("client request message")
/************************************************************
*Function    : opcdata_transferClientReq
*Action      : transfer client request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.30
*Instruction : null
************************************************************/
static int opcdata_transferClientReq(struct filter_header *hdr, OPCDATA_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Send request eventbuffer */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session req buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send request buffer */
		if ((NULL != buff) && (0 < len))
		{
			if (0 != buffer_sendtofwd(hdr, buff, len))
			{
				SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opcdata_checkWriteUuid
*Action      : check write uuid
*Input       : uuid     interface uuid
			   callId   call id
			   session  session obj
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.2.8
*Instruction : null
************************************************************/
static void opcdata_checkWriteUuid(void *uuid, unsigned int callId, OPCDATA_SESSION *session)
{
	OPC_INTERFACE_INDEX index;
	OPC_UUID *puuid = NULL;

	puuid = (OPC_UUID *)uuid;
	SCLogInfo("[%s:%d]uuid(%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x), callId(%u)",
		__func__, __LINE__,
		puuid->timeLow, puuid->timeMid, puuid->timeHiAndVersion,
		puuid->clockSeq[0], puuid->clockSeq[1],
		puuid->node[0], puuid->node[1], puuid->node[2], puuid->node[3], puuid->node[4], puuid->node[5],
		callId);

	for (index = ISYSTEMACTIVATOR_ID; index < INTERFACE_BUTT_ID; index++)
	{
		if (0 == memcmp(uuid, (void *)&(g_interfaceTables[index].uuid), sizeof(OPC_UUID)))
		{
			session->callId = callId;
			session->interfaceId = index;
			SCLogInfo("[%s:%d]interface tables hit id(%d), callId(%u)", __func__, __LINE__, index, callId);
		}
	}

	return;
}

/************************************************************
*Function    : opcdata_isWriteReq
*Action      : check write request
*Input       : null
*Output      : null
*Return      : PARSER_BTRUE    write request
			   PARSER_BFALSE   not write request
*Author      : liuzongquan(000932)
*Date        : 2017.2.8
*Instruction : null
************************************************************/
static int opcdata_isWriteReq(unsigned short interfaceId, unsigned short opnum)
{
	SCLogInfo("[%s:%d]interfaceId(%u), opnum(%u)", __func__, __LINE__, interfaceId, opnum);
	switch (interfaceId)
	{
	case IOPCSYNCIO_ID:
	case IOPCASYNCIO_ID:
	case IOPCASYNCIO2_ID:
	case IOPCITEMIO_ID:
	case IOPCSYNCIO2_ID:
	case IOPCASYNCIO3_ID:
	{
		if (g_interfaceTables[interfaceId].opnumMapping[4].opnum == opnum)
		{
			return PARSER_BTRUE;
		}
		break;
	}

	default:
	{
		break;
	}
	}

	return PARSER_BFALSE;
}

/************************************************************
*Function    : opcdata_checkCltEventReqbufData
*Action      : check the full session in reqbuf
*Input       : hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int opcdata_checkCltEventReqbufData(struct filter_header *hdr, OPCDATA_SESSION *session, OPC_DATA_MODE dataMode)
{
	ev_ssize_t ret;
	size_t reqBufLen;
	OPC_HEAD opcHead;
	OPC_UUID uuid;
	OPC_REQUEST requestHead;
	unsigned char content[OPC_BUFF_DATA_LEN];

	while (1)
	{
		/* Get data length of client request eventbuffer */
		reqBufLen = evbuffer_get_length(session->reqBuf);
		if (0 >= reqBufLen)
		{
			break;
		}

		/* Check head data all receive */
		if (OPC_HEAD_LEN >= reqBufLen)
		{
			break;
		}

		ret = evbuffer_copyout(session->reqBuf, (void *)&opcHead, sizeof(OPC_HEAD));
		if (-1 == ret)
		{
			SCLogError("[%s:%d]copy data from req buff failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		opc_convHead(&opcHead);

		if ((0x05 != opcHead.version) || ((0x00 != opcHead.version_minor) && (0x01 != opcHead.version_minor)))
		{
			SCLogError("[%s:%d]invalid opc head, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		if (reqBufLen < opcHead.fragLength)
		{
			break;
		}

		if ((0x0b == opcHead.packetType) || (0x0e == opcHead.packetType))
		{
			/* Bind(11) || Alter_context(14) */
			ret = evbuffer_copyout(session->reqBuf, (void *)content, OPC_HEAD_LEN + OPC_HEAD_BIND_LEN + OPC_CTX_ITEM_LEN);
			if (-1 == ret)
			{
				SCLogError("[%s:%d]copy data from req buff failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}

			memcpy((void *)&uuid, content + OPC_HEAD_LEN + OPC_HEAD_BIND_LEN + 4, sizeof(OPC_UUID));
			if (opcHead.dataRepresentation[0] & 0x10)
			{
				/* Small end */
				opc_convUuid(1, &uuid);
			}
			else
			{
				opc_convUuid(0, &uuid);
			}

			opcdata_checkWriteUuid((void *)&uuid, opcHead.callId, session);
		}
		else if (0x00 == opcHead.packetType)
		{
			/* Request(0) */
			if (OPC_DATA_R == dataMode)
			{
				ret = evbuffer_copyout(session->reqBuf, (void *)content, OPC_HEAD_LEN + OPC_REQ_HEAD_LEN);
				if (-1 == ret)
				{
					SCLogError("[%s:%d]copy data from req buff failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
					return PARSER_ERROR;
				}

				memcpy((void *)&requestHead, content + OPC_HEAD_LEN, sizeof(OPC_REQUEST));
				if (opcHead.dataRepresentation[0] & 0x10)
				{
					/* Small end */
					opc_convRequestHead(1, &requestHead);
				}
				else
				{
					opc_convRequestHead(0, &requestHead);
				}

				if (opcdata_isWriteReq(session->interfaceId, requestHead.opnum))
				{
					session->callId = opcHead.callId;
					session->opnum = requestHead.opnum;

					opcdata_writeSeceventLog(hdr, (int)(opcHead.fragLength), "Reject opcdata write");
					if (OPC_DATA_DROP == g_opcdataConfig.dataRule)
					{
						/* drop */
						if (0 != evbuffer_drain(session->reqBuf, (size_t)opcHead.fragLength))
						{
							SCLogError("[%s:%d]drain data from session req buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
							return PARSER_ERROR;
						}
						continue;
					}
					else if (OPC_DATA_CLOSE == g_opcdataConfig.dataRule)
					{
						/* close */
						return PARSER_ERROR;
					}
				}
			}
		}

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, opcHead.fragLength))
		{
			SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opcdata_checkCltReqbufData
*Action      : check the full session in buff
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : because you want to format the application data,
			   you need to identify the integrity of the application data
************************************************************/
static int opcdata_checkCltReqbufData(struct filter_header *hdr, OPCDATA_SESSION *session,
	OPC_DATA_MODE dataMode, const void *buff, size_t len)
{
	OPC_HEAD opcHead;
	OPC_UUID uuid;
	OPC_REQUEST requestHead;

	while (1)
	{
		/* Check data length of request buff */
		if (0 >= len)
		{
			break;
		}

		/* Check head data all receive */
		if (OPC_HEAD_LEN >= len)
		{
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}

			break;
		}

		memcpy((void *)&opcHead, buff, sizeof(OPC_HEAD));
		opc_convHead(&opcHead);

		if ((0x05 != opcHead.version) || ((0x00 != opcHead.version_minor) && (0x01 != opcHead.version_minor)))
		{
			SCLogError("[%s:%d]invalid opc head, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		if (len < opcHead.fragLength)
		{
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
			break;
		}

		if ((0x0b == opcHead.packetType) || (0x0e == opcHead.packetType))
		{
			/* Bind(11) || Alter_context(14) */
			memcpy((void *)&uuid, buff + OPC_HEAD_LEN + OPC_HEAD_BIND_LEN + 4, sizeof(OPC_UUID));
			if (opcHead.dataRepresentation[0] & 0x10)
			{
				/* Small end */
				opc_convUuid(1, &uuid);
			}
			else
			{
				opc_convUuid(0, &uuid);
			}

			opcdata_checkWriteUuid((void *)&uuid, opcHead.callId, session);
		}
		else if (0x00 == opcHead.packetType)
		{
			/* Request(0) */
			if (OPC_DATA_R == dataMode)
			{
				memcpy((void *)&requestHead, buff + OPC_HEAD_LEN, sizeof(OPC_REQUEST));
				if (opcHead.dataRepresentation[0] & 0x10)
				{
					/* Small end */
					opc_convRequestHead(1, &requestHead);
				}
				else
				{
					opc_convRequestHead(0, &requestHead);
				}

				if (opcdata_isWriteReq(session->interfaceId, requestHead.opnum))
				{
					session->callId = opcHead.callId;
					session->opnum = requestHead.opnum;

					opcdata_writeSeceventLog(hdr, (int)(opcHead.fragLength), "Reject opcdata write");
					if (OPC_DATA_DROP == g_opcdataConfig.dataRule)
					{
						/* drop */
						buff += opcHead.fragLength;
						len -= opcHead.fragLength;
						continue;
					}
					else if (OPC_DATA_CLOSE == g_opcdataConfig.dataRule)
					{
						return PARSER_ERROR;
					}
				}
			}
		}

		if (0 != buffer_sendtofwd(hdr, buff, opcHead.fragLength))
		{
			SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		buff += opcHead.fragLength;
		len -= opcHead.fragLength;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opcdata_checkClientReq
*Action      : check client request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.30
*Instruction : null
************************************************************/
static int opcdata_checkClientReq(struct filter_header *hdr, OPCDATA_SESSION *session,
	OPC_DATA_MODE dataMode, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Send request eventbuffer */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session req buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}

		if (PARSER_OK != opcdata_checkCltEventReqbufData(hdr, session, dataMode))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send request buffer */
		if ((NULL != buff) && (0 < len))
		{
			if (PARSER_OK != opcdata_checkCltReqbufData(hdr, session, dataMode, buff, len))
			{
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opcdata_handleClientReq
*Action      : handle client request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int opcdata_handleClientReq(struct filter_header *hdr, OPCDATA_SESSION *session, const void *buff, size_t len)
{
	if (NULL == hdr->private)
	{
		SCLogError("[%s:%d]hdr private info is null, ssid(%u)", __func__, __LINE__, hdr->sessionid);
		return opcdata_transferClientReq(hdr, session, buff, len);
	}

	if (OPC_DATA_RW == opc_getDataMode(hdr->svr->parent_acldata->groupname))
	{
		return opcdata_checkClientReq(hdr, session, OPC_DATA_RW, buff, len);
	}
	else
	{
		SCLogInfo("[%s:%d]read-only mode, ssid(%u)", __func__, __LINE__, hdr->sessionid);
		return opcdata_checkClientReq(hdr, session, OPC_DATA_R, buff, len);
	}
}
#endif

#if GAP_DESC("server request message")
/************************************************************
*Function    : opcdata_handleServerReq
*Action      : handle server request
*Input       : hdr          packet processing header information
			   session      session obj
			   buff         data buffer
			   len          data buffer len
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int opcdata_handleServerReq(struct filter_header *hdr, OPCDATA_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		/* Send request eventbuffer */
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session req buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, 0))
		{
			SCLogError("[%s:%d]send session buffer data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send request buffer */
		if ((NULL != buff) && (0 < len))
		{
			if (0 != buffer_sendtofwd(hdr, buff, len))
			{
				SCLogError("[%s:%d]send data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

/************************************************************
*Function    : opcdata_checkFwdObjData
*Action      : check form forward obj data
*Input       : hdr          packet processing header information
			   obj          data obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2017.1.3
*Instruction : null
************************************************************/
static int opcdata_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
{
	if (obj->cmd != FWDCMD_FORWARDDATA)
	{
		SCLogError("[%s:%d]not fwd event type, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}

	if (0 == obj->has_buffdata)
	{
		SCLogError("[%s:%d]obj data is null, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

#if GAP_DESC("client response message")
/************************************************************
*Function    : opcdata_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int opcdata_handleClientRsp(struct filter_header *hdr, OPCDATA_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		/* Send response eventbuffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[%s:%d]add data to session rsp buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
		{
			SCLogError("[%s:%d]send session buffer data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send response buffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[%s:%d]send data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server response message")
/************************************************************
*Function    : opcdata_handleClientRsp
*Action      : handle client response
*Input       : obj          data obj
			   hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int opcdata_handleServerRsp(struct filter_header *hdr, OPCDATA_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		/* Send response eventbuffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[%s:%d]add data to session rsp buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}

		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, 0))
		{
			SCLogError("[%s:%d]send session buffer data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}
	else
	{
		/* Send response buffer */
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			if (0 != buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[%s:%d]send data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

/************************************************************
*Function    : opcdata_data
*Action      : opcdata protocol data processing
*Input       : hdr  packet processing header information
			   ev   data packet processing type
			   buff data
			   len  data len
*Output      : null
*Return      : FLTRET_CLOSE     close session
			   FLTRET_OK        normal processing
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static enum FLT_RET opcdata_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	OPCDATA_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("[%s:%d]invalid para, hdr(%p)", __func__, __LINE__, hdr);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = opcdata_allocSession();
		if (session == NULL)
		{
			SCLogError("[%s:%d]create new session failed, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
			return FLTRET_CLOSE;
		}

		hdr->user = session;
		session->connecting = OPC_CONNECTING;
		SCLogInfo("[%s:%d]connect in, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		break;
	}

	case FLTEV_ONSVROK:         /* Connect to server success or failure */
	{
		int isok;

		if (NULL == hdr->user)
		{
			SCLogError("[%s:%d]invalid para, hdr(%p), user(%p)", __func__, __LINE__, hdr, hdr->user);
			return opcdata_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(int) != (unsigned int)len))
		{
			SCLogError("[%s:%d]invalid para, buff(%p), len(%u)", __func__, __LINE__, buff, (unsigned int)len);
			return opcdata_closeSession(hdr, (int)len, "Invalid socket len");
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			SCLogError("[%s:%d]connect server failed, sock(%d), ssid(%u)", __func__, __LINE__, isok, hdr->sessionid);
			return opcdata_closeSession(hdr, (int)len, "Invalid socket fd");
		}

		SCLogInfo("[%s:%d]connect server success, sock(%d), ssid(%u)", __func__, __LINE__, isok, hdr->sessionid);

		session = hdr->user;
		session->connecting = OPC_CONNECTED;
		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return opcdata_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}

		break;
	}

	case FLTEV_ONSOCKDATA:      /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[%s:%d]invalid para, hdr(%p), user(%p)", __func__, __LINE__, hdr, hdr->user);
			return opcdata_closeSession(hdr, (int)len, "User data is NULL");
		}

		session = hdr->user;

		SCLogInfo("[%s:%d]on socket data, len(%u), sessionid(%u)", __func__, __LINE__, (unsigned int)len, hdr->sessionid);

		if (OPC_DISCONNECT == session->connecting)
		{
			/* Has not handshake, receive data, not handle */
			SCLogWarning("[%s:%d]svr not connect, not progress.... ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return FLTRET_OK;
		}

		if (OPC_CONNECTING == session->connecting)
		{
			if ((NULL != buff) && (0 < len))
			{
				/* Connecting, receive data, add to req buffer, when connected and brush out */
				if (0 != evbuffer_add(session->reqBuf, buff, len))
				{
					SCLogError("[%s:%d]add data to session buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
					return opcdata_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("[%s:%d]svr not ready, delay.... ssid(%u)", __func__, __LINE__, hdr->sessionid);
			}
			return FLTRET_OK;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != opcdata_handleClientReq(hdr, session, buff, len))
			{
				return opcdata_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (PARSER_OK != opcdata_handleServerReq(hdr, session, buff, len))
			{
				return opcdata_closeSession(hdr, (int)len, "Handle server request data");
			}
		}

		break;
	}

	case FLTEV_ONFWDDATA:       /* Receive data from arbitration-machine */
	{
		ForwardObject *obj = NULL;

		if (NULL == hdr->user)
		{
			SCLogError("[%s:%d]invalid para, hdr(%p), user(%p)", __func__, __LINE__, hdr, hdr->user);
			return opcdata_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("[%s:%d]invalid para, buff(%p), len(%u)", __func__, __LINE__, buff, (unsigned int)len);
			return opcdata_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		SCLogInfo("[%s:%d]receive data from fwd, len(%u), sessionid(%u)", __func__, __LINE__,
			(unsigned int)obj->buffdata.len, hdr->sessionid);

		if (PARSER_OK != opcdata_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != opcdata_handleClientRsp(hdr, session, obj))
			{
				return opcdata_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != opcdata_handleServerRsp(hdr, session, obj))
			{
				return opcdata_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return opcdata_closeSession(hdr, 0, NULL);
	}

	default:                    /* Not handle, return ok */
		break;

	}

	return FLTRET_OK;
}

/************************************************************
*Function    : opcdata_free
*Action      : opcdata free
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opcdata_free(void)
{
	g_opcdataConfig.dataRule = OPC_DATA_DROP;
	return FLTRET_OK;
}

/************************************************************
*Function    : opcdata_init
*Action      : opcdata init
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opcdata_init(void)
{
	g_opcdataConfig.dataRule = OPC_DATA_DROP;
	return FLTRET_OK;
}

/************************************************************
*Function    : opcdata_checkData
*Action      : opcdata check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID opcdata_checkData(const void *buff, size_t len)
{
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_opcdata
*Action      : opcdata protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static struct packet_filter g_filter_opcdata =
{
	SVR_ID_OPCDATA,
	"opcdata parser",
	opcdata_init,
	opcdata_data,
	opcdata_free,
	opcdata_checkData
};

void parser_opc_data_pktfilter_reg()
{
	pktfilter_reg(&g_filter_opcdata);
}

void parser_opc_data_pktfilter_unreg()
{
	pktfilter_unreg(&g_filter_opcdata);
}