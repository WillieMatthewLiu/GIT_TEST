/********************************************************************************

		   Copyright (C), 2016, 2016, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_opc.c
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2016.12.28
Description    : OPC protocol process
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
#include "lib/memory.h"
#include "gapconfig.h"
#include "parser_tcp.h"
#include "db_mysql.h"
#include "parser_common.h"
#include "gap_cmd_group.h"
#include "parser_opc.h"
#include "memtypes.h"

/* OPC Interface Tables */
OPC_INTERFACE_TABLE g_interfaceTables[INTERFACE_BUTT_ID] =
{
	{
		"ISystemActivator",
		{0x000001a0, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
		{
			{-1, NULL}
		}
	},

	{
		"IOXIDResolver",
		{0x99fcfec4, 0x5260, 0x101b, {0xbb, 0xcb}, {0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a}},
		{
			{-1, NULL}
		}
	},

	{
		"IRemUnknown2",
		{0x00000143, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
		{
			{-1, NULL}
		}
	},

	{
		"IOPCCommon",
		{0xf31dfde2, 0x07b6, 0x11d2, {0xb2, 0xd8}, {0x00, 0x60, 0x08, 0x3b, 0xa1, 0xfb}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "SetLocaleID"},
			{4,  "GetLocaleID"},
			{5,  "QueryAvailableLocaleIDs"},
			{6,  "GetErrorString"},
			{7,  "SetClientName"},
			{-1, NULL}
		}
	},

	{
		"IOPCServerList",
		{0x13486d50, 0x4821, 0x11d2, {0xa4, 0x94}, {0x3c, 0xb3, 0x06, 0xc1, 0x00, 0x00}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "EnumClassesOfCategories"},
			{4,  "GetClassDetails"},
			{5,  "CLSIDFromProgID"},
			{-1, NULL}
		}
	},

	{
		"IOPCServerList2",
		{0x9dd0b56c, 0xad9e, 0x43ee, {0x83, 0x05}, {0x48, 0x7f, 0x31, 0x88, 0xbf, 0x7a}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "EnumClassesOfCategories"},
			{4,  "GetClassDetails"},
			{5,  "CLSIDFromProgID"},
			{-1, NULL}
		}
	},

	{
		"IOPCServer",
		{0x39c13a4d, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "AddGroup"},
			{4,  "GetErrorString"},
			{5,  "GetGroupByName"},
			{6,  "GetStatus"},
			{7,  "RemoveGroup"},
			{8,  "CreateGroupEnumerator"},
			{-1, NULL}
		}
	},

	{
		"IConnectionPointContainer",
		{0xb196b284, 0xbab4, 0x101a, {0xb6, 0x9c}, {0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07}},
		{
			{-1, NULL}
		}
	},

	{
		"IConnectionPoint",
		{0xb196b286, 0xbab4, 0x101a, {0xb6, 0x9c}, {0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07}},
		{
			{-1, NULL}
		}
	},

	{
		"IOPCBrowseServerAddressSpace",
		{0x39c13a4f, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "QueryOrganization"},
			{4,  "ChangeBrowsePosition"},
			{5,  "BrowseOPCItemIDs"},
			{6,  "GetItemID"},
			{7,  "BrowseAccessPaths"},
			{-1, NULL}
		}
	},

	{
		"IEnumGUID",
		{0x0002e000, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
		{
			{-1, NULL}
		}
	},

	{
		"IEnumString",
		{0x00000101, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
		{
			{-1, NULL}
		}
	},

	{
		"IEnumOPCItemAttributes",
		{0x39c13a55, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "Next"},
			{4,  "Skip"},
			{5,  "Reset"},
			{6,  "Clone"},
			{-1, NULL}
		}
	},

	{
		"IOPCGroupStateMgt",
		{0x39c13a50, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "GetState"},
			{4,  "SetState"},
			{5,  "SetName"},
			{6,  "CloneGroup"},
			{-1, NULL}
		}
	},

	{
		"IOPCItemMgt",
		{0x39c13a54, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "AddItems"},
			{4,  "ValidateItems"},
			{5,  "RemoveItems"},
			{6,  "SetActiveState"},
			{7,  "SetClientHandles"},
			{8,  "SetDatatypes"},
			{9,  "CreateEnumerator"},
			{-1, NULL}
		}
	},

	{
		"IOPCItemProperties",
		{0x39c13a72, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "QueryAvailableProperties"},
			{4,  "GetItemProperties"},
			{5,  "LookupItemIDs"},
			{-1, NULL}
		}
	},

	{
		"IOPCDataCallback",
		{0x39c13a70, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "OnDataChange"},
			{4,  "OnReadComplete"},
			{5,  "OnWriteComplete"},
			{6,  "OnCancelComplete"},
			{-1, NULL}
		}
	},

	{
		"IOPCSyncIO",
		{0x39c13a52, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "Read"},
			{4,  "Write"},
			{-1, NULL}
		}
	},

	{
		"IOPCAsyncIO",
		{0x39c13a53, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "Read"},
			{4,  "Write"},
			{5,  "Refresh"},
			{6,  "Cancel"},
			{-1, NULL}
		}
	},

	{
		"IOPCAsyncIO2",
		{0x39c13a71, 0x011e, 0x11d0, {0x96, 0x75}, {0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "Read"},
			{4,  "Write"},
			{5,  "Refresh2"},
			{6,  "Cancel2"},
			{7,  "SetEnable"},
			{8,  "GetEnable"},
			{-1, NULL}
		}
	},

	{
		"IOPCItemIO",
		{0x85c0b427, 0x2893, 0x4cbc, {0xbd, 0x78}, {0xe5, 0xfc, 0x51, 0x46, 0xf0, 0x8f}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "Read"},
			{4,  "WriteVQT"},
			{-1, NULL}
		}
	},

	{
		"IOPCSyncIO2",
		{0x730f5f0f, 0x55b1, 0x4c81, {0x9e, 0x18}, {0xff, 0x8a, 0x09, 0x04, 0xe1, 0xfa}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "ReadMaxAge"},
			{4,  "WriteVQT"},
			{-1, NULL}
		}
	},

	{
		"IOPCAsyncIO3",
		{0x0967b97b, 0x36ef, 0x423e, {0xb6, 0xf8}, {0x6b, 0xff, 0x1e, 0x40, 0xd3, 0x9d}},
		{
			{0,  "QueryInterface"},
			{1,  "AddRef"},
			{2,  "Release"},
			{3,  "ReadMaxAge"},
			{4,  "WriteVQT"},
			{5,  "RefreshMaxAge"},
			{-1, NULL}
		}
	}
};

/* VMOPC(unicode) */
static unsigned char g_opcDataSign[OPC_DATA_SIGN_LEN] = { 0x56, 0x00, 0x4d, 0x00, 0x4f, 0x00, 0x50, 0x00, 0x43, 0x00 };

/* System port number */
static unsigned short g_opcDynamicPortNum = 0;

/* Dynamic port service information */
static OPC_DYNAMIC_PORT *g_opcDynamicPort = NULL;

/* Opc config list head */
struct list_head g_opcConfigHead;

/************************************************************
*Function    : opc_allocSession
*Action      : apply session and assign the initial value
*Input       : null
*Output      : null
*Return      : session  success
			   NULL     false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static OPC_SESSION *opc_allocSession(void)
{
	OPC_SESSION *session = NULL;

	session = SCMalloc(sizeof(OPC_SESSION));
	if (NULL == session)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, (unsigned int)sizeof(OPC_SESSION));
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
	session->isReqbufSend = PARSER_BFALSE;
	session->routes = NULL;
	return session;
}

/************************************************************
*Function    : opc_freeSession
*Action      : free session
*Input       : session  session information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_freeSession(struct filter_header *hdr, OPC_SESSION *session)
{
	OPC_NEW_ROUTE *opcRoute = NULL;

	evbuffer_free(session->rspBuf);
	session->rspBuf = NULL;
	evbuffer_free(session->reqBuf);
	session->reqBuf = NULL;
	while (session->routes)
	{
		opcRoute = session->routes;
		session->routes = opcRoute->next;
		if (ROUTE_MAPPED != hdr->routetype)
		{
			if (opcRoute->data_svr)
			{
				if (opcRoute->data_svr->name)
				{
					SCFree(opcRoute->data_svr->name);
					opcRoute->data_svr->name = SCStrdup(NAT_SVR_NAME);
				}
			}
		}
		SCFree(opcRoute);
		opcRoute = NULL;
	}
	SCFree(session);
	session = NULL;
	return;
}

/************************************************************
*Function    : opc_existRoute
*Action      : check route of serverPort exist
*Input       : serverPort   server port
*Output      : dynamicPort  new port
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.3.16
*Instruction : null
************************************************************/
static int opc_existRoute(unsigned short serverPort, unsigned short *dynamicPort)
{
	unsigned short index;

	for (index = 0; index < g_opcDynamicPortNum; index++)
	{
		if (g_opcDynamicPort[index].isUsed)
		{
			if (g_opcDynamicPort[index].svr->dstport == serverPort)
			{
				*dynamicPort = g_opcDynamicPort[index].svr->localport;
				return PARSER_BTRUE;
			}
		}
	}

	return PARSER_BFALSE;
}

/************************************************************
*Function    : opc_getPort
*Action      : get service mapping information
*Input       : svr service mapping information
*Output      : null
*Return      : returned new service port    success
			   0                            failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static unsigned short opc_getPort(void)
{
	unsigned short index;

	for (index = 0; index < g_opcDynamicPortNum; index++)
	{
		if (!g_opcDynamicPort[index].isUsed)
		{
			g_opcDynamicPort[index].isUsed = PARSER_BTRUE;
			return index + g_gapcfg->port_opc_begin;
		}
	}

	return 0;
}

/************************************************************
*Function    : opc_setPort
*Action      : set service mapping information
*Input       : svr service mapping information
*Output      : null
*Return      : returned new service port    success
			   0                            failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_setPort(unsigned short localPort, struct server *svr)
{
	unsigned short index;

	if ((g_gapcfg->port_opc_begin > localPort) || (g_gapcfg->port_opc_end < localPort))
	{
		SCLogError("[%s:%d]invalid port(%u), range[%u, %u]!\n", __func__, __LINE__,
			localPort, g_gapcfg->port_opc_begin, g_gapcfg->port_opc_end);
		return PARSER_ERROR;
	}

	index = localPort - g_gapcfg->port_opc_begin;
	if (!g_opcDynamicPort[index].isUsed)
	{
		SCLogError("[%s:%d]localPort(%u) not used!\n", __func__, __LINE__, localPort);
		return PARSER_ERROR;
	}

	g_opcDynamicPort[index].svr = svr;
	return PARSER_OK;
}

/************************************************************
*Function    : opc_deletePort
*Action      : delete service mapping information
*Input       : svr  service mapping information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_deletePort(struct server *svr)
{
	unsigned short index;

	for (index = 0; index < g_opcDynamicPortNum; index++)
	{
		if (g_opcDynamicPort[index].isUsed)
		{
			if (g_opcDynamicPort[index].svr == svr)
			{
				g_opcDynamicPort[index].svr = NULL;
				g_opcDynamicPort[index].isUsed = PARSER_BFALSE;
			}
		}
	}
	return;
}

/************************************************************
*Function    : opc_writeSeceventLog
*Action      : security log
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.27
*Instruction : null
************************************************************/
static void opc_writeSeceventLog(struct filter_header *hdr, int packLen, char *content)
{
	char sip[OPC_IP_BUFF_LEN];
	char dip[OPC_IP_BUFF_LEN];
	char *proto = NULL;
	uint32_t *autoId = NULL;
	struct acl_data *aclData = NULL;

	addr2str(hdr->ip->saddr, sip);
	addr2str(hdr->ip->daddr, dip);
	proto = (char*)server_strfromid(SVR_ID_OPC);
	GET_AUTO_ID_BY_HDR(hdr, &autoId);
	aclData = (struct acl_data *)(hdr->private);

	INSERT_ACCESSAUDIT_LOG(autoId, sip, dip, 6, (int)(hdr->tcp->source), (int)(hdr->tcp->dest), proto,
		aclData->user, "none", l_critical, aclData->groupname, "false", packLen, content);
}

/************************************************************
*Function    : opc_closeSession
*Action      : close session
*Input       : hdr      packet processing header information
			   content  description
*Output      : null
*Return      : FLTRET_CLOSE
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static enum FLT_RET opc_closeSession(struct filter_header *hdr, int packLen, char *content)
{
	OPC_SESSION *session = NULL;

	if ((NULL == hdr) || (NULL == hdr->user))
	{
		SCLogError("[%s:%d]invalid para, hdr(%p), user(%p), maybe session is closed", __func__, __LINE__, hdr, hdr->user);
		return FLTRET_CLOSE;
	}

	if (content)
	{
		opc_writeSeceventLog(hdr, packLen, content);
	}

	session = hdr->user;

	opc_freeSession(hdr, session);
	hdr->user = NULL;

	SCLogInfo("[%s:%d]on socket close, ssid(%u)", __func__, __LINE__, hdr->sessionid);

	return FLTRET_CLOSE;
}

/************************************************************
*Function    : opc_getLittleEndianU16
*Action      : little end sequence to U16
*Input       : netValue network value
*Output      : null
*Return      : local value
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static unsigned short opc_getLittleEndianU16(unsigned short netValue)
{
	return ((*((unsigned char *)(&netValue))) | ((*((unsigned char *)(&netValue) + 1)) << 8));
}

/************************************************************
*Function    : opc_getBigEndianU16
*Action      : big end sequence to U16
*Input       : netValue network value
*Output      : null
*Return      : local value
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static unsigned short opc_getBigEndianU16(unsigned short netValue)
{
	return ((*((unsigned char *)(&netValue)) << 8) | (*((unsigned char *)(&netValue) + 1)));
}

/************************************************************
*Function    : opc_getLittleEndianU32
*Action      : little end sequence to U32
*Input       : netValue network value
*Output      : null
*Return      : local value
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static unsigned int opc_getLittleEndianU32(unsigned int netValue)
{
	return ((*((unsigned char *)(&netValue))) | ((*((unsigned char *)(&netValue) + 1)) << 8)
		| ((*((unsigned char *)(&netValue) + 2)) << 16) | ((*((unsigned char *)(&netValue) + 3)) << 24));
}

/************************************************************
*Function    : opc_getBigEndianU32
*Action      : big end sequence to U32
*Input       : netValue network value
*Output      : null
*Return      : local value
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static unsigned int opc_getBigEndianU32(unsigned int netValue)
{
	return ((*((unsigned char *)(&netValue)) << 24) | ((*((unsigned char *)(&netValue) + 1)) << 16)
		| ((*((unsigned char *)(&netValue) + 2)) << 8) | (*((unsigned char *)(&netValue) + 3)));
}

/************************************************************
*Function    : opc_convHead
*Action      : convert OPC header information
*Input       : opcHead  head
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
void opc_convHead(OPC_HEAD *opcHead)
{
	if (NULL != opcHead)
	{
		if (opcHead->dataRepresentation[0] & 0x10)
		{
			/* Small end */
			opcHead->fragLength = opc_getLittleEndianU16(opcHead->fragLength);
			opcHead->authLength = opc_getLittleEndianU16(opcHead->authLength);
			opcHead->callId = opc_getLittleEndianU32(opcHead->callId);
		}
		else
		{
			opcHead->fragLength = opc_getBigEndianU16(opcHead->fragLength);
			opcHead->authLength = opc_getBigEndianU16(opcHead->authLength);
			opcHead->callId = opc_getBigEndianU32(opcHead->callId);
		}
	}
	return;
}

/************************************************************
*Function    : opc_convUuid
*Action      : convert UUID information
*Input       : flag  byte order mark (1: small end 0: end)
			   uuid  uuid information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
void opc_convUuid(unsigned char flag, OPC_UUID *uuid)
{
	if (NULL != uuid)
	{
		if (flag)
		{
			uuid->timeLow = opc_getLittleEndianU32(uuid->timeLow);
			uuid->timeMid = opc_getLittleEndianU16(uuid->timeMid);
			uuid->timeHiAndVersion = opc_getLittleEndianU16(uuid->timeHiAndVersion);
		}
		else
		{
			uuid->timeLow = opc_getBigEndianU32(uuid->timeLow);
			uuid->timeMid = opc_getBigEndianU16(uuid->timeMid);
			uuid->timeHiAndVersion = opc_getBigEndianU16(uuid->timeHiAndVersion);
		}
	}
	return;
}

/************************************************************
*Function    : opc_convRequestHead
*Action      : convert head request information
*Input       : flag         byte order mark (1: small end 0: end)
			   requestHead  request head information
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
void opc_convRequestHead(unsigned char flag, OPC_REQUEST *requestHead)
{
	if (NULL != requestHead)
	{
		if (flag)
		{
			requestHead->allocHint = opc_getLittleEndianU32(requestHead->allocHint);
			requestHead->contextId = opc_getLittleEndianU16(requestHead->contextId);
			requestHead->opnum = opc_getLittleEndianU16(requestHead->opnum);
		}
		else
		{
			requestHead->allocHint = opc_getBigEndianU32(requestHead->allocHint);
			requestHead->contextId = opc_getBigEndianU16(requestHead->contextId);
			requestHead->opnum = opc_getBigEndianU16(requestHead->opnum);
		}
	}
	return;
}

#if GAP_DESC("client request message")
/************************************************************
*Function    : opc_checkCltEventReqbufData
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
static int opc_checkCltEventReqbufData(struct filter_header *hdr, OPC_SESSION *session)
{
	ev_ssize_t ret;
	size_t eventBufLen;
	OPC_HEAD opcHead;
	OPC_REQUEST *requestHead = NULL;
	OPC_CTX_ITEM *opcCtxItem = NULL;
	unsigned char content[OPC_BUFF_DATA_LEN];

	while (1)
	{
		/* Get data length of client request eventbuffer */
		eventBufLen = evbuffer_get_length(session->reqBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check head data all receive */
		if (OPC_HEAD_LEN >= eventBufLen)
		{
			break;
		}

		/* Get opc head */
		ret = evbuffer_copyout(session->reqBuf, (void *)&opcHead, sizeof(OPC_HEAD));
		if (-1 == ret)
		{
			SCLogError("[%s:%d]copy data from req buff failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
		opc_convHead(&opcHead);

		/* Check head valid */
		if ((0x05 != opcHead.version) || ((0x00 != opcHead.version_minor) && (0x01 != opcHead.version_minor)))
		{
			SCLogError("[%s:%d]invalid opc head, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		/* Check body data all receive */
		if (eventBufLen < opcHead.fragLength)
		{
			break;
		}

		/* Check this whole session */
		if ((0x0b == opcHead.packetType) || (0x0e == opcHead.packetType))
		{
			/* Bind(11) || Alter_context(14) */
			ret = evbuffer_copyout(session->reqBuf, (void *)content, OPC_HEAD_LEN + OPC_HEAD_BIND_LEN + OPC_CTX_ITEM_LEN);
			if (-1 == ret)
			{
				SCLogError("[%s:%d]copy data from req buff failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
			opcCtxItem = (OPC_CTX_ITEM *)(content + OPC_HEAD_LEN + OPC_HEAD_BIND_LEN);

			if (opcHead.dataRepresentation[0] & 0x10)
			{
				/* Small end */
				opc_convUuid(1, &(opcCtxItem->uuid));
			}
			else
			{
				opc_convUuid(0, &(opcCtxItem->uuid));
			}

			if (0 == memcmp((void *)&(opcCtxItem->uuid),
				(void *)&(g_interfaceTables[ISYSTEMACTIVATOR_ID].uuid),
				sizeof(OPC_UUID)))
			{
				session->callId = opcHead.callId;
				session->interfaceId = ISYSTEMACTIVATOR_ID;
			}
			else if (0 == memcmp((void *)&(opcCtxItem->uuid),
				(void *)&(g_interfaceTables[IOXIDRESOLVER_ID].uuid),
				sizeof(OPC_UUID)))
			{
				session->callId = opcHead.callId;
				session->interfaceId = IOXIDRESOLVER_ID;
			}
			else
			{
				session->callId = PARSER_INVALUE32;
				session->interfaceId = PARSER_INVALUE16;
			}
		}
		else if (0x00 == opcHead.packetType)
		{
			/* Request(0) */
			ret = evbuffer_copyout(session->reqBuf, (void *)content, OPC_HEAD_LEN + OPC_REQ_HEAD_LEN);
			if (-1 == ret)
			{
				SCLogError("[%s:%d]copy data from req buff failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
			requestHead = (OPC_REQUEST *)(content + OPC_HEAD_LEN);

			if (opcHead.dataRepresentation[0] & 0x10)
			{
				/* Small end */
				opc_convRequestHead(1, requestHead);
			}
			else
			{
				opc_convRequestHead(0, requestHead);
			}

			if ((ISYSTEMACTIVATOR_ID == session->interfaceId) || (IOXIDRESOLVER_ID == session->interfaceId))
			{
				session->callId = opcHead.callId;
				session->opnum = requestHead->opnum;
			}
		}

		/* send this session to fwd */
		if (0 != evbuffer_sendtofwd(hdr, session->reqBuf, opcHead.fragLength))
		{
			SCLogError("[%s:%d]send session buffer data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opc_checkCltReqbufData
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
static int opc_checkCltReqbufData(struct filter_header *hdr, OPC_SESSION *session, const void *buff, size_t len)
{
	OPC_HEAD opcHead;
	OPC_CTX_ITEM opcCtxItem;
	OPC_REQUEST requestHead;

	while (1)
	{
		/* Get data length of client request buff */
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

		/* Get opc head */
		memcpy((void *)&opcHead, buff, sizeof(OPC_HEAD));
		opc_convHead(&opcHead);

		/* Check head valid */
		if ((0x05 != opcHead.version) || ((0x00 != opcHead.version_minor) && (0x01 != opcHead.version_minor)))
		{
			SCLogError("[%s:%d]invalid opc head, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		/* Check body data all receive */
		if (len < opcHead.fragLength)
		{
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
			break;
		}

		/* Check this whole session */
		if ((0x0b == opcHead.packetType) || (0x0e == opcHead.packetType))
		{
			/* Bind(11) || Alter_context(14) */
			memcpy((void *)&opcCtxItem, buff + OPC_HEAD_LEN + OPC_HEAD_BIND_LEN, OPC_CTX_ITEM_LEN);
			if (opcHead.dataRepresentation[0] & 0x10)
			{
				/* Small end */
				opc_convUuid(1, &(opcCtxItem.uuid));
			}
			else
			{
				opc_convUuid(0, &(opcCtxItem.uuid));
			}

			if (0 == memcmp((void *)&(opcCtxItem.uuid),
				(void *)&(g_interfaceTables[ISYSTEMACTIVATOR_ID].uuid),
				sizeof(OPC_UUID)))
			{
				session->callId = opcHead.callId;
				session->interfaceId = ISYSTEMACTIVATOR_ID;
			}
			else if (0 == memcmp((void *)&(opcCtxItem.uuid),
				(void *)&(g_interfaceTables[IOXIDRESOLVER_ID].uuid),
				sizeof(OPC_UUID)))
			{
				session->callId = opcHead.callId;
				session->interfaceId = IOXIDRESOLVER_ID;
			}
			else
			{
				session->callId = PARSER_INVALUE32;
				session->interfaceId = PARSER_INVALUE16;
			}
		}
		else if (0x00 == opcHead.packetType)
		{
			/* Request(0) */
			memcpy((void *)&requestHead, buff + OPC_HEAD_LEN, OPC_REQ_HEAD_LEN);
			if (opcHead.dataRepresentation[0] & 0x10)
			{
				/* Small end */
				opc_convRequestHead(1, &requestHead);
			}
			else
			{
				opc_convRequestHead(0, &requestHead);
			}

			if ((ISYSTEMACTIVATOR_ID == session->interfaceId) || (IOXIDRESOLVER_ID == session->interfaceId))
			{
				session->callId = opcHead.callId;
				session->opnum = requestHead.opnum;
			}
		}

		/* send this session to fwd */
		if (0 != buffer_sendtofwd(hdr, buff, opcHead.fragLength))
		{
			SCLogError("[%s:%d]send session buffer data to forward failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
		buff += opcHead.fragLength;
		len -= opcHead.fragLength;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opc_handleClientReq
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
static int opc_handleClientReq(struct filter_header *hdr, OPC_SESSION *session, const void *buff, size_t len)
{
	if (0 < evbuffer_get_length(session->reqBuf))
	{
		if ((NULL != buff) && (0 < len))
		{
			/* Add data to request eventbuffer */
			if (0 != evbuffer_add(session->reqBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session req buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
		}

		/* Client handle: req buffer and this data */
		if (PARSER_OK != opc_checkCltEventReqbufData(hdr, session))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		if ((NULL != buff) && (0 < len))
		{
			/* Client handle: this data */
			if (PARSER_OK != opc_checkCltReqbufData(hdr, session, buff, len))
			{
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server request message")
/************************************************************
*Function    : opc_handleServerReq
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
static int opc_handleServerReq(struct filter_header *hdr, OPC_SESSION *session, const void *buff, size_t len)
{
	/* Send request eventbuffer */
	if (0 < evbuffer_get_length(session->reqBuf))
	{
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
*Function    : opc_checkFwdObjData
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
static int opc_checkFwdObjData(struct filter_header *hdr, ForwardObject *obj)
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
*Function    : opc_getIsaPort
*Action      : get port information in the packet
*Input       : data     data
			   len      data length
*Output      : serverPort   server port
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_getIsaPort(unsigned char *data, unsigned short len, unsigned short *serverPort)
{
	char *endPos = NULL;
	char *startPos = NULL;
	unsigned char *analyAddr = NULL;
	char content[OPC_ANALY_RESULT_LEN];

	while (NULL != (analyAddr = memchr(data, 'V', len)))
	{
		(void)wide2Char((char *)analyAddr, OPC_ANALY_CONTENT_LEN, content, OPC_ANALY_RESULT_LEN);
		if (0 == strncmp(content, "VMOPC", OPC_DATA_KEY_LEN))
		{
			if (NULL != (startPos = strchr(content, '[')))
			{
				endPos = strchr(startPos, ']');
				if (NULL == endPos)
				{
					SCLogError("[%s:%d]invalid content(%s)", __func__, __LINE__, content);
					break;
				}
				*endPos = '\0';
				*serverPort = (unsigned short)atoi(startPos + 1);
				return PARSER_OK;
			}
		}

		data = analyAddr + 1;
		len -= (analyAddr - data);
	}

	return PARSER_ERROR;
}

/************************************************************
*Function    : opc_setSvrToSession
*Action      : add svr information to session
*Input       : session  session
			   svr      service mapping information
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_setSvrToSession(OPC_SESSION *session, struct server *svr)
{
	OPC_NEW_ROUTE *opcRoute = NULL;

	opcRoute = (OPC_NEW_ROUTE *)SCMalloc(sizeof(OPC_NEW_ROUTE));
	if (NULL == opcRoute)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, (unsigned int)sizeof(OPC_NEW_ROUTE));
		return PARSER_ERROR;
	}

	opcRoute->data_svr = svr;
	opcRoute->next = session->routes;
	session->routes = opcRoute;

	return PARSER_OK;
}

/************************************************************
*Function    : opc_svrDelCallback
*Action      : callback when delete svr
*Input       : svr
			   args     port
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.5.17
*Instruction : null
************************************************************/
static void opc_svrDelCallback(struct server *svr, void *args)
{
	unsigned short localPort;

	if ((NULL == svr) || (NULL == args))
	{
		SCLogError("[%s:%d]invalid args, svr(%p), args(%p)", __func__, __LINE__, svr, args);
		return;
	}

	localPort = *((unsigned short *)args);
	SCFree(args);
	args = NULL;

	opc_deletePort(svr);

	SCLogInfo("[%s:%d]free dynamic port(%u), svr(%p)", __func__, __LINE__, localPort, svr);
}

/************************************************************
*Function    : opc_createDataSvr
*Action      : generate data port session and record in command port session
*Input       : hdr          packet processing header information
			   serverPort   server port
			   dstIp        dest ip
			   localIp      local ip
			   dynamicPort  new port
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_createDataSvr(struct filter_header *hdr, unsigned short serverPort,
	char *dstIp, char *localIp, unsigned short *dynamicPort)
{
	unsigned short localPort;
	unsigned short *portArg = NULL;
	struct server *svr = NULL;
	OPC_SESSION *session = NULL;

	if (opc_existRoute(serverPort, dynamicPort))
	{
		SCLogInfo("[%s:%d]exist route(serverPort:%u dynamicPort:%u), sessionid(%u)",
			__func__, __LINE__, serverPort, *dynamicPort, hdr->sessionid);
		return PARSER_OK;
	}

	if (0 == (localPort = opc_getPort()))
	{
		SCLogError("[%s:%d]can't find valid opc port, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}
	*dynamicPort = localPort;

	if (NULL != localIp)
	{
		if (NULL != dstIp)
		{
			if (ROUTE_MAPPED == hdr->routetype)
			{
				svr = server_new(SVR_ID_OPCDATA, NAT_SVR_NAME, localIp, localPort, dstIp, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(%u), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, localIp, localPort, dstIp, serverPort, hdr->sessionid);
			}
			else
			{
				svr = server_new(SVR_ID_OPCDATA, "opc svr", localIp, 0, dstIp, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(0), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, localIp, dstIp, serverPort, hdr->sessionid);
			}
		}
		else
		{
			if (ROUTE_MAPPED == hdr->routetype)
			{
				svr = server_new(SVR_ID_OPCDATA, NAT_SVR_NAME, localIp, localPort, hdr->svr->dstip, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(%u), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, localIp, localPort, hdr->svr->dstip, serverPort, hdr->sessionid);
			}
			else
			{
				svr = server_new(SVR_ID_OPCDATA, "opc svr", localIp, 0, hdr->svr->dstip, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(0), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, localIp, hdr->svr->dstip, serverPort, hdr->sessionid);
			}
		}
	}
	else
	{
		if (NULL != dstIp)
		{
			if (ROUTE_MAPPED == hdr->routetype)
			{
				svr = server_new(SVR_ID_OPCDATA, NAT_SVR_NAME, hdr->svr->localip, localPort, dstIp, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(%u), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, hdr->svr->localip, localPort, dstIp, serverPort, hdr->sessionid);
			}
			else
			{
				svr = server_new(SVR_ID_OPCDATA, "opc svr", hdr->svr->localip, 0, dstIp, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(0), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, hdr->svr->localip, dstIp, serverPort, hdr->sessionid);
			}
		}
		else
		{
			if (ROUTE_MAPPED == hdr->routetype)
			{
				svr = server_new(SVR_ID_OPCDATA, NAT_SVR_NAME, hdr->svr->localip, localPort, hdr->svr->dstip, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(%u), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, hdr->svr->localip, localPort, hdr->svr->dstip, serverPort, hdr->sessionid);
			}
			else
			{
				svr = server_new(SVR_ID_OPCDATA, "opc svr", hdr->svr->localip, 0, hdr->svr->dstip, serverPort);
				SCLogInfo("[%s:%d]add opc data route success, svr(%p), localIp(%s), localPort(0), " \
					"dstIp(%s), serverPort(%u), sessionid(%u)", __func__, __LINE__,
					svr, hdr->svr->localip, hdr->svr->dstip, serverPort, hdr->sessionid);
			}
		}
	}

	if (svr == NULL)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u), sessionid(%u)", __func__, __LINE__,
			(unsigned int)sizeof(struct server), hdr->sessionid);
		return PARSER_ERROR;
	}

	portArg = (unsigned short *)SCMalloc(sizeof(unsigned short));
	if (NULL == portArg)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u), sessionid(%u)", __func__, __LINE__,
			(unsigned int)sizeof(unsigned short), hdr->sessionid);
		return PARSER_ERROR;
	}
	*portArg = localPort;
	server_setfreecb(svr, opc_svrDelCallback, portArg);

	if (PARSER_OK != opc_setPort(localPort, svr))
	{
		opc_deletePort(svr);
		server_free(svr);
		svr = NULL;
		return PARSER_ERROR;
	}

	if (0 != hdr->svr_add_cb(hdr, svr))
	{
		SCLogError("[%s:%d]svr_add_cb failed, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		opc_deletePort(svr);
		server_free(svr);
		svr = NULL;
		return PARSER_ERROR;
	}

	session = hdr->user;
	if (PARSER_OK != opc_setSvrToSession(session, svr))
	{
		if (0 != hdr->svr_remove_cb(hdr, svr))
		{
			SCLogError("[%s:%d]svr_remove_cb failed, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		}
		opc_deletePort(svr);
		server_free(svr);
		svr = NULL;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opc_ip2ToUnicode
*Action      : IP conversion to OPC protocol network format
*Input       : ipIn             ip string input cache
			   ipOut            ip string output cache
			   ipOutLen         output cache length
			   unicodeOutLen    Output effective length
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : [2002:xxxx:xxxx::xxxx:xxxx]
************************************************************/
static int opc_ip2ToUnicode(char *ipIn, char *ipOut, int ipOutLen, unsigned short *unicodeOutLen)
{
	int ret;
	int ip1;
	int ip2;
	int ip3;
	int ip4;
	char ip2Str[OPC_IP2_BUFF_LEN];

	ret = sscanf(ipIn, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
	if (4 != ret)   /* 4: four filed of ip string */
	{
		SCLogError("[%s:%d]invalid ip string(%s)!\n", __func__, __LINE__, ipIn);
		return PARSER_ERROR;
	}

	if (((0 <= ip1) && (255 >= ip1))
		&& ((0 <= ip2) && (255 >= ip2))
		&& ((0 <= ip3) && (255 >= ip3))
		&& ((0 <= ip4) && (255 >= ip4)))
	{
		snprintf(ip2Str, OPC_IP2_BUFF_LEN, "2002:%x%02x:%x%02x::%x%02x:%x%02x", ip1, ip2, ip3, ip4, ip1, ip2, ip3, ip4);
	}
	else
	{
		SCLogError("[%s:%d]invalid ip string(%s)!\n", __func__, __LINE__, ipIn);
		return PARSER_ERROR;
	}

	(void)char2Wide(ip2Str, strlen(ip2Str), ipOut, ipOutLen);
	*unicodeOutLen = (unsigned short)strlen(ip2Str) * OPC_CHAR_WIDE_SIZE;

	return PARSER_OK;
}

/************************************************************
*Function    : opc_replaceParse
*Action      : data replace
*Input       : analyAddr        to check data
			   data             unchecked data
			   len              unchecked data length
			   writePos         new data write cursor
			   newDataLen       new data length
			   analyLen         to check data length
			   unicodeOldLen    data length to be replaced
			   unicodeNewData   replacement data
			   unicodeNewLen    replace data length
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_replaceParse(unsigned char **analyAddr, unsigned char **data, unsigned short *len,
	unsigned char **writePos, unsigned short *newDataLen,
	unsigned short *analyLen, unsigned short unicodeOldLen,
	unsigned char *unicodeNewData, unsigned short unicodeNewLen)
{
	int  strLen;

	/* Write data in front of old Unicode data */
	strLen = *analyAddr - *data;
	memcpy(*writePos, *data, strLen);
	*writePos += strLen;
	*newDataLen += strLen;
	*data += strLen;
	*len -= strLen;
	*analyLen = *len;

	/* Write Unicode data NEW */
	memcpy(*writePos, unicodeNewData, unicodeNewLen);
	*writePos += unicodeNewLen;
	*newDataLen += unicodeNewLen;

	/* Skip old Unicode data, update analysis data*/
	*data += unicodeOldLen;
	*len -= unicodeOldLen;
	*analyAddr = *data;
	*analyLen = *len;

	return;
}

/************************************************************
*Function    : opc_reduceOutputUnused
*Action      : remove unused part of output data
*Input       : data             data
			   reduceLen        remove data length
			   opcIsaThatOutput ISA output data structure
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_reduceOutputUnused(unsigned char *data, int reduceLen, ISA_RCINSTANCE_THAT_PROP_OUTPUT *opcIsaThatOutput)
{
	unsigned int gapCount32;
	unsigned short gapCount16;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;
	ISA_RCINSTANCE_THAT *opcIsaThat = NULL;
	ISA_RCINSTANCE_THAT_CUS *opcIsaThatCusHead = NULL;

	gapCount16 = (unsigned short)reduceLen;
	gapCount32 = (unsigned int)reduceLen;
	gapCount16 = htons(gapCount16);
	gapCount32 = htonl(gapCount32);

	/* Update total length */
	opcHead = (OPC_HEAD *)data;
	if (opcHead->dataRepresentation[0] & 0x10)
	{
		/* Small end */
		gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
		gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
	}

	/* Update total length */
	opcHead->fragLength -= gapCount16;

	/* Update hit length */
	opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
	opcResp->allocHint -= gapCount32;

	/* Update Data ObJ length */
	opcIsaThat = (ISA_RCINSTANCE_THAT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN);
	opcIsaThat->cntData1 -= gapCount32;
	opcIsaThat->cntData2 -= gapCount32;
	opcIsaThat->size -= gapCount32;
	opcIsaThat->totalsize -= gapCount32;

	/* Update CustomHeader length */
	opcIsaThatCusHead = (ISA_RCINSTANCE_THAT_CUS *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN + sizeof(ISA_RCINSTANCE_THAT));
	opcIsaThatCusHead->totalSize -= gapCount32;
	opcIsaThatCusHead->clsSizesPtr.propertyDataSize1 -= gapCount32;

	/* Update CUSTOMOBJREF->IActProperties->Properties->PropertiesOutput */
	opcIsaThatOutput->PrivateHeader.ObjectBufferLength -= gapCount32;
}

/************************************************************
*Function    : opc_increaseOutputUnused
*Action      : add unused part of output data
*Input       : data             data
			   increaseLen      add data length
			   opcIsaThatOutput ISA output data structure
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_increaseOutputUnused(unsigned char *data, int increaseLen, ISA_RCINSTANCE_THAT_PROP_OUTPUT *opcIsaThatOutput)
{
	unsigned int gapCount32;
	unsigned short gapCount16;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;
	ISA_RCINSTANCE_THAT *opcIsaThat = NULL;
	ISA_RCINSTANCE_THAT_CUS *opcIsaThatCusHead = NULL;

	gapCount16 = (unsigned short)increaseLen;
	gapCount32 = (unsigned int)increaseLen;
	gapCount16 = htons(gapCount16);
	gapCount32 = htonl(gapCount32);

	/* Update total length */
	opcHead = (OPC_HEAD *)data;
	if (opcHead->dataRepresentation[0] & 0x10)
	{
		/* Small end */
		gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
		gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
	}

	/* Update total length */
	opcHead->fragLength += gapCount16;

	/* Update hit length */
	opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
	opcResp->allocHint += gapCount32;

	/* Update Data ObJ length */
	opcIsaThat = (ISA_RCINSTANCE_THAT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN);
	opcIsaThat->cntData1 += gapCount32;
	opcIsaThat->cntData2 += gapCount32;
	opcIsaThat->size += gapCount32;
	opcIsaThat->totalsize += gapCount32;

	/* Update CustomHeader length */
	opcIsaThatCusHead = (ISA_RCINSTANCE_THAT_CUS *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN + sizeof(ISA_RCINSTANCE_THAT));
	opcIsaThatCusHead->totalSize += gapCount32;
	opcIsaThatCusHead->clsSizesPtr.propertyDataSize1 += gapCount32;

	/* Update CUSTOMOBJREF->IActProperties->Properties->PropertiesOutput */
	opcIsaThatOutput->PrivateHeader.ObjectBufferLength += gapCount32;
}

/************************************************************
*Function    : opc_reduceReplyUnused
*Action      : reduce unused portion of answer data
*Input       : data             data
			   reduceLen        reduce data length
			   opcIsaThatReply  ISA reply data structure
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_reduceReplyUnused(unsigned char *data, int reduceLen, ISA_RCINSTANCE_THAT_PROP_REPLY *opcIsaThatReply)
{
	unsigned int gapCount32;
	unsigned short gapCount16;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;
	ISA_RCINSTANCE_THAT *opcIsaThat = NULL;
	ISA_RCINSTANCE_THAT_CUS *opcIsaThatCusHead = NULL;

	gapCount16 = (unsigned short)reduceLen;
	gapCount32 = (unsigned int)reduceLen;
	gapCount16 = htons(gapCount16);
	gapCount32 = htonl(gapCount32);

	/* Update total length */
	opcHead = (OPC_HEAD *)data;
	if (opcHead->dataRepresentation[0] & 0x10)
	{
		/* Small end */
		gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
		gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
	}

	/* Update total length */
	opcHead->fragLength -= gapCount16;

	/* Update hit length */
	opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
	opcResp->allocHint -= gapCount32;

	/* Update Data ObJ length */
	opcIsaThat = (ISA_RCINSTANCE_THAT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN);
	opcIsaThat->cntData1 -= gapCount32;
	opcIsaThat->cntData2 -= gapCount32;
	opcIsaThat->size -= gapCount32;
	opcIsaThat->totalsize -= gapCount32;

	/* Update CustomHeader length */
	opcIsaThatCusHead = (ISA_RCINSTANCE_THAT_CUS *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN + sizeof(ISA_RCINSTANCE_THAT));
	opcIsaThatCusHead->totalSize -= gapCount32;
	opcIsaThatCusHead->clsSizesPtr.propertyDataSize2 -= gapCount32;

	/* Update CUSTOMOBJREF->IActProperties->Properties->ScmReplyInfo */
	opcIsaThatReply->PrivateHeader.ObjectBufferLength -= gapCount32;
}

/************************************************************
*Function    : opc_increaseReplyUnused
*Action      : add unused part of answer data
*Input       : data             data
			   increaseLen      add data length
			   opcIsaThatReply  ISA reply data structure
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_increaseReplyUnused(unsigned char *data, int increaseLen, ISA_RCINSTANCE_THAT_PROP_REPLY *opcIsaThatReply)
{
	unsigned int gapCount32;
	unsigned short gapCount16;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;
	ISA_RCINSTANCE_THAT *opcIsaThat = NULL;
	ISA_RCINSTANCE_THAT_CUS *opcIsaThatCusHead = NULL;

	gapCount16 = (unsigned short)increaseLen;
	gapCount32 = (unsigned int)increaseLen;
	gapCount16 = htons(gapCount16);
	gapCount32 = htonl(gapCount32);

	/* Update total length */
	opcHead = (OPC_HEAD *)data;
	if (opcHead->dataRepresentation[0] & 0x10)
	{
		/* Small end */
		gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
		gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
	}

	/* Update total length */
	opcHead->fragLength += gapCount16;

	/* Update hit length */
	opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
	opcResp->allocHint += gapCount32;

	/* Update Data ObJ length */
	opcIsaThat = (ISA_RCINSTANCE_THAT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN);
	opcIsaThat->cntData1 += gapCount32;
	opcIsaThat->cntData2 += gapCount32;
	opcIsaThat->size += gapCount32;
	opcIsaThat->totalsize += gapCount32;

	/* Update CustomHeader length */
	opcIsaThatCusHead = (ISA_RCINSTANCE_THAT_CUS *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN + sizeof(ISA_RCINSTANCE_THAT));
	opcIsaThatCusHead->totalSize += gapCount32;
	opcIsaThatCusHead->clsSizesPtr.propertyDataSize2 += gapCount32;

	/* Update CUSTOMOBJREF->IActProperties->Properties->ScmReplyInfo */
	opcIsaThatReply->PrivateHeader.ObjectBufferLength += gapCount32;
}

/************************************************************
*Function    : opc_updataIsaUnused
*Action      : update unused area length
*Input       : data         data
			   len          data length
			   ipOffset     ip offset
			   portOffset   port offset
*Output      : null
*Return      : returnLen    increase or decrease length
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_updataIsaUnused(unsigned char *data, unsigned short len, int ipOffset, int portOffset)
{
	int tempLen;
	int returnLen;
	int unusedLen;
	int totalOffset;
	unsigned int outputOrReplydataLen;
	unsigned short offset;
	unsigned short leftLen;
	unsigned char *endAddr = NULL;
	OPC_HEAD *opcHead = NULL;
	unsigned char *leftAddr = NULL;
	ISA_RCINSTANCE_THAT_CUS *opcIsaThatCusHead = NULL;
	ISA_RCINSTANCE_THAT_PROP_OUTPUT *opcIsaThatOutput = NULL;
	ISA_RCINSTANCE_THAT_PROP_REPLY *opcIsaThatReply = NULL;

	leftLen = 0;
	tempLen = 0;
	returnLen = 0;
	unusedLen = 0;

	/* get output unused bytes length */
	opcHead = (OPC_HEAD *)data;
	opcIsaThatCusHead = (ISA_RCINSTANCE_THAT_CUS *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN + sizeof(ISA_RCINSTANCE_THAT));
	opcIsaThatOutput = (ISA_RCINSTANCE_THAT_PROP_OUTPUT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN
		+ sizeof(ISA_RCINSTANCE_THAT)
		+ sizeof(ISA_RCINSTANCE_THAT_CUS));
	if (opcHead->dataRepresentation[0] & 0x10)
	{
		/* Small end */
		offset = OPC_MEM_OFFSET(ISA_RCINSTANCE_THAT_PROP_OUTPUT,
			InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.NumEntries)
			+ (opc_getLittleEndianU16(opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.NumEntries) * 2)
			+ 4;
		outputOrReplydataLen = opc_getLittleEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize1);
	}
	else
	{
		offset = OPC_MEM_OFFSET(ISA_RCINSTANCE_THAT_PROP_OUTPUT,
			InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.NumEntries)
			+ (opc_getBigEndianU16(opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.NumEntries) * 2)
			+ 4;
		outputOrReplydataLen = opc_getBigEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize1);
	}
	endAddr = (unsigned char *)opcIsaThatOutput + outputOrReplydataLen;
	unusedLen = (int)(outputOrReplydataLen - (unsigned int)offset);

	//SCLogInfo("[%s:%d]outputOrReplydataLen:%u offset:%u", __func__, __LINE__, outputOrReplydataLen, offset);
	//SCLogInfo("[%s:%d]outputUnusedLen:%d", __func__, __LINE__, unusedLen);
	if (0 != ipOffset)
	{
		if (0 > ipOffset)
		{
			/* Reduce */
			if (8 <= (unusedLen - ipOffset))
			{
				/* Reduced length + unused length exceeding 8 bytes, unused length set to exceeding part */
				tempLen = ((unusedLen - ipOffset) % 8) - unusedLen;
				opc_reduceOutputUnused(data, (unusedLen - ((unusedLen - ipOffset) % 8)), opcIsaThatOutput);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memcpy(endAddr - (unusedLen - ((unusedLen - ipOffset) % 8)), leftAddr, leftLen);
				len -= (unsigned short)(unusedLen - ((unusedLen - ipOffset) % 8));
			}
			else
			{
				tempLen = ipOffset * (-1);
				opc_increaseOutputUnused(data, tempLen, opcIsaThatOutput);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memset(endAddr, 0, tempLen);
				memcpy(endAddr + tempLen, leftAddr, leftLen);
				len += (unsigned short)tempLen;
			}
		}
		else
		{
			/* Increase */
			if (ipOffset > unusedLen)
			{
				tempLen = (((ipOffset + 8) / 8) * 8) - ipOffset;
				opc_increaseOutputUnused(data, tempLen, opcIsaThatOutput);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memset(endAddr, 0, tempLen);
				memcpy(endAddr + tempLen, leftAddr, leftLen);
				len += (unsigned short)tempLen;
			}
			else
			{
				tempLen = ipOffset * (-1);
				opc_reduceOutputUnused(data, ipOffset, opcIsaThatOutput);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memcpy(endAddr - ipOffset, leftAddr, leftLen);
				len -= ipOffset;
			}
		}
		SCFree(leftAddr);
		leftAddr = NULL;
	}
	returnLen = tempLen;

	//SCLogInfo("[%s:%d]update after: %u", __func__, __LINE__, opcIsaThatCusHead->clsSizesPtr.propertyDataSize1);
	//SCLogInfo("[%s:%d]update data1:%u data2:%u", __func__, __LINE__,
	//           opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData1,
	//           opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData2);

	if (tempLen < 0)
	{
		outputOrReplydataLen -= (unsigned int)(tempLen * (-1));
	}
	else
	{
		outputOrReplydataLen += (unsigned int)tempLen;
	}

	//SCLogInfo("[%s:%d]outputOrReplydataLen:%u", __func__, __LINE__, outputOrReplydataLen);
	opcIsaThatReply = (ISA_RCINSTANCE_THAT_PROP_REPLY *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN
		+ sizeof(ISA_RCINSTANCE_THAT)
		+ sizeof(ISA_RCINSTANCE_THAT_CUS)
		+ outputOrReplydataLen);
	if (opcHead->dataRepresentation[0] & 0x10)
	{
		/* Small end */
		offset = OPC_MEM_OFFSET(ISA_RCINSTANCE_THAT_PROP_REPLY,
			RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.NumEntries)
			+ (opc_getLittleEndianU16(opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.NumEntries) * 2)
			+ 4;
		outputOrReplydataLen = opc_getLittleEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize2);
	}
	else
	{
		offset = OPC_MEM_OFFSET(ISA_RCINSTANCE_THAT_PROP_REPLY,
			RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.NumEntries)
			+ (opc_getBigEndianU16(opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.NumEntries) * 2)
			+ 4;
		outputOrReplydataLen = opc_getBigEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize2);
	}
	endAddr = (unsigned char *)opcIsaThatReply + outputOrReplydataLen;
	unusedLen = (int)(outputOrReplydataLen - (unsigned int)offset);

	//SCLogInfo("[%s:%d]outputOrReplydataLen:%u offset:%u", __func__, __LINE__, outputOrReplydataLen, offset);
	//SCLogInfo("[%s:%d]replyUnusedLen:%d", __func__, __LINE__, unusedLen);

	totalOffset = ipOffset + portOffset;
	if (0 != totalOffset)
	{
		if (0 > totalOffset)
		{
			/* Reduce */
			if (8 <= (unusedLen - totalOffset))
			{
				/* Reduced length + unused length exceeding 8 bytes, unused length set to exceeding part */
				tempLen = ((unusedLen - totalOffset) % 8) - unusedLen;
				opc_reduceReplyUnused(data, (unusedLen - ((unusedLen - totalOffset) % 8)), opcIsaThatReply);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memcpy(endAddr - (unusedLen - ((unusedLen - totalOffset) % 8)), leftAddr, leftLen);
				len -= (unsigned short)(unusedLen - ((unusedLen - totalOffset) % 8));
			}
			else
			{
				tempLen = totalOffset * (-1);
				opc_increaseReplyUnused(data, tempLen, opcIsaThatReply);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memset(endAddr, 0, tempLen);
				memcpy(endAddr + tempLen, leftAddr, leftLen);
				len += tempLen;
			}
		}
		else
		{
			/* Increase */
			if (totalOffset > unusedLen)
			{
				tempLen = (((totalOffset + 8) / 8) * 8) - totalOffset;
				opc_increaseReplyUnused(data, tempLen, opcIsaThatReply);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memset(endAddr, 0, tempLen);
				memcpy(endAddr + tempLen, leftAddr, leftLen);
				len += tempLen;
			}
			else
			{
				tempLen = totalOffset * (-1);
				opc_reduceReplyUnused(data, totalOffset, opcIsaThatReply);
				leftLen = len - (endAddr - data);
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, endAddr, leftLen);
				memcpy(endAddr - totalOffset, leftAddr, leftLen);
				len -= totalOffset;
			}
		}
		SCFree(leftAddr);
		leftAddr = NULL;
	}
	returnLen += tempLen;

	SCLogInfo("[%s:%d]update isa unused, returnLen:%d", __func__, __LINE__, returnLen);

	return returnLen;
}

/************************************************************
*Function    : opc_updateIsaLenInfo
*Action      : update ISystemActivator response data length information
*Input       : data         data
			   len          data length
			   newLen       new length
			   ipOffset     ip offset
			   portOffset   port offset
*Output      : null
*Return      : returnLen    increase or decrease length
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_updateIsaLenInfo(unsigned char *data, unsigned short len, unsigned short newLen, int ipOffset, int portOffset)
{
	int totalOffset;
	unsigned int newOutputLen;
	unsigned int gapCount32;
	unsigned short gapCount16;
	unsigned short ipGapCount16;
	unsigned int ipGapCount32;
	unsigned short ipPortGapCount16;
	unsigned int ipPortGapCount32;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;
	ISA_RCINSTANCE_THAT *opcIsaThat = NULL;
	ISA_RCINSTANCE_THAT_CUS *opcIsaThatCusHead = NULL;
	ISA_RCINSTANCE_THAT_PROP_OUTPUT *opcIsaThatOutput = NULL;
	ISA_RCINSTANCE_THAT_PROP_REPLY *opcIsaThatReply = NULL;

	opcHead = (OPC_HEAD *)data;

	SCLogInfo("[%s:%d]ISA, len:%u, newLen:%u, ipOffset:%d, portOffset:%d",
		__func__, __LINE__, len, newLen, ipOffset, portOffset);

	/* Update total length */
	if (len > newLen)
	{
		/* Reduce */
		gapCount16 = (unsigned short)(len - newLen);
		gapCount32 = (unsigned int)(len - newLen);

		gapCount16 = htons(gapCount16);
		gapCount32 = htonl(gapCount32);
		if (opcHead->dataRepresentation[0] & 0x10)
		{
			/* Small end */
			gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
			gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
		}

		/* Update total length */
		opcHead->fragLength -= gapCount16;

		/* Update hit length */
		opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
		opcResp->allocHint -= gapCount32;

		/* Update Data ObJ length */
		opcIsaThat = (ISA_RCINSTANCE_THAT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN);
		opcIsaThat->cntData1 -= gapCount32;
		opcIsaThat->cntData2 -= gapCount32;
		opcIsaThat->size -= gapCount32;
		opcIsaThat->totalsize -= gapCount32;

		/* Update CustomHeader length */
		opcIsaThatCusHead = (ISA_RCINSTANCE_THAT_CUS *)(data
			+ OPC_HEAD_LEN
			+ OPC_RSP_HEAD_LEN
			+ sizeof(ISA_RCINSTANCE_THAT));
		opcIsaThatCusHead->totalSize -= gapCount32;
	}
	else
	{
		/* Increase */
		gapCount16 = (unsigned short)(newLen - len);
		gapCount32 = (unsigned int)(newLen - len);

		gapCount16 = htons(gapCount16);
		gapCount32 = htonl(gapCount32);
		if (opcHead->dataRepresentation[0] & 0x10)
		{
			/* Small end */
			gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
			gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
		}

		/* Update total length */
		opcHead->fragLength += gapCount16;

		/* Update hit length */
		opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
		opcResp->allocHint += gapCount32;

		/* Update Data ObJ length */
		opcIsaThat = (ISA_RCINSTANCE_THAT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN);
		opcIsaThat->cntData1 += gapCount32;
		opcIsaThat->cntData2 += gapCount32;
		opcIsaThat->size += gapCount32;
		opcIsaThat->totalsize += gapCount32;

		/* Update CustomHeader length */
		opcIsaThatCusHead = (ISA_RCINSTANCE_THAT_CUS *)(data
			+ OPC_HEAD_LEN
			+ OPC_RSP_HEAD_LEN
			+ sizeof(ISA_RCINSTANCE_THAT));
		opcIsaThatCusHead->totalSize += gapCount32;
	}

	newOutputLen = 0;
	if (0 != ipOffset)
	{
		if (0 > ipOffset)
		{
			ipGapCount16 = (unsigned short)(ipOffset * (-1));
			ipGapCount32 = (unsigned int)(ipOffset * (-1));
			ipGapCount16 = htons(ipGapCount16);
			ipGapCount32 = htonl(ipGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipGapCount16 = BYTE_SEQ_SWITCH_16(ipGapCount16);
				ipGapCount32 = BYTE_SEQ_SWITCH_32(ipGapCount32);
			}
			opcIsaThatCusHead->clsSizesPtr.propertyDataSize1 -= ipGapCount32;
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				newOutputLen = opc_getLittleEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize1);
			}
			else
			{
				newOutputLen = opc_getBigEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize1);
			}

			/* Update CUSTOMOBJREF->IActProperties->Properties->PropertiesOutput */
			opcIsaThatOutput = (ISA_RCINSTANCE_THAT_PROP_OUTPUT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN
				+ sizeof(ISA_RCINSTANCE_THAT)
				+ sizeof(ISA_RCINSTANCE_THAT_CUS));
			opcIsaThatOutput->PrivateHeader.ObjectBufferLength -= ipGapCount32;
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData1 -= ipGapCount32;
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData2 -= ipGapCount32;

			ipGapCount16 = (ipGapCount16 / 2);
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.NumEntries -= ipGapCount16;
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.SecurityOffset -= ipGapCount16;
		}
		else
		{
			ipGapCount16 = (unsigned short)ipOffset;
			ipGapCount32 = (unsigned int)ipOffset;
			ipGapCount16 = htons(ipGapCount16);
			ipGapCount32 = htonl(ipGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipGapCount16 = BYTE_SEQ_SWITCH_16(ipGapCount16);
				ipGapCount32 = BYTE_SEQ_SWITCH_32(ipGapCount32);
			}
			opcIsaThatCusHead->clsSizesPtr.propertyDataSize1 += ipGapCount32;
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				newOutputLen = opc_getLittleEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize1);
			}
			else
			{
				newOutputLen = opc_getBigEndianU32(opcIsaThatCusHead->clsSizesPtr.propertyDataSize1);
			}

			/* Update CUSTOMOBJREF->IActProperties->Properties->PropertiesOutput */
			opcIsaThatOutput = (ISA_RCINSTANCE_THAT_PROP_OUTPUT *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN
				+ sizeof(ISA_RCINSTANCE_THAT)
				+ sizeof(ISA_RCINSTANCE_THAT_CUS));
			opcIsaThatOutput->PrivateHeader.ObjectBufferLength += ipGapCount32;
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData1 += ipGapCount32;
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData2 += ipGapCount32;

			ipGapCount16 = (ipGapCount16 / 2);
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.NumEntries += ipGapCount16;
			opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.OBJREF.ResolerAddress.SecurityOffset += ipGapCount16;
		}
	}

	totalOffset = ipOffset + portOffset;
	if (0 != totalOffset)
	{
		if (0 > totalOffset)
		{
			ipPortGapCount16 = (unsigned short)(totalOffset * (-1));
			ipPortGapCount32 = (unsigned int)(totalOffset * (-1));
			ipPortGapCount16 = htons(ipPortGapCount16);
			ipPortGapCount32 = htonl(ipPortGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipPortGapCount16 = BYTE_SEQ_SWITCH_16(ipPortGapCount16);
				ipPortGapCount32 = BYTE_SEQ_SWITCH_32(ipPortGapCount32);
			}
			opcIsaThatCusHead->clsSizesPtr.propertyDataSize2 -= ipPortGapCount32;

			/* Update CUSTOMOBJREF->IActProperties->Properties->ScmReplyInfo */
			opcIsaThatReply = (ISA_RCINSTANCE_THAT_PROP_REPLY *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN
				+ sizeof(ISA_RCINSTANCE_THAT)
				+ sizeof(ISA_RCINSTANCE_THAT_CUS)
				+ newOutputLen);
			opcIsaThatReply->PrivateHeader.ObjectBufferLength -= ipPortGapCount32;

			ipPortGapCount16 = (ipPortGapCount16 / 2);
			ipPortGapCount32 = (ipPortGapCount32 / 2);
			opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.oxid -= ipPortGapCount32;
			opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.NumEntries -= ipPortGapCount16;
			opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.SecurityOffset -= ipPortGapCount16;
		}
		else
		{
			ipPortGapCount16 = (unsigned short)totalOffset;
			ipPortGapCount32 = (unsigned int)totalOffset;
			ipPortGapCount16 = htons(ipPortGapCount16);
			ipPortGapCount32 = htonl(ipPortGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipPortGapCount16 = BYTE_SEQ_SWITCH_16(ipPortGapCount16);
				ipPortGapCount32 = BYTE_SEQ_SWITCH_32(ipPortGapCount32);
			}
			opcIsaThatCusHead->clsSizesPtr.propertyDataSize2 += ipPortGapCount32;

			/* Update CUSTOMOBJREF->IActProperties->Properties->ScmReplyInfo */
			opcIsaThatReply = (ISA_RCINSTANCE_THAT_PROP_REPLY *)(data + OPC_HEAD_LEN + OPC_RSP_HEAD_LEN
				+ sizeof(ISA_RCINSTANCE_THAT)
				+ sizeof(ISA_RCINSTANCE_THAT_CUS)
				+ newOutputLen);
			opcIsaThatReply->PrivateHeader.ObjectBufferLength += ipPortGapCount32;

			ipPortGapCount16 = (ipPortGapCount16 / 2);
			ipPortGapCount32 = (ipPortGapCount32 / 2);
			opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.oxid += ipPortGapCount32;
			opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.NumEntries += ipPortGapCount16;
			opcIsaThatReply->RemoteRequestPtr.RemoteReply.OxidBindingsPtr.OxidBindings.Bindings.SecurityOffset += ipPortGapCount16;
		}
	}

	//SCLogInfo("[%s:%d]len1:%u len2:%u", __func__, __LINE__,
	//           opcIsaThatCusHead->clsSizesPtr.propertyDataSize1,
	//           opcIsaThatCusHead->clsSizesPtr.propertyDataSize2);
	//SCLogInfo("[%s:%d]data1:%u data2:%u", __func__, __LINE__,
	//           opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData1,
	//           opcIsaThatOutput->InterfacePtrsPtr.InterfacePtr.Interface.CntData2);

	/* No processing area */
	return opc_updataIsaUnused(data, newLen, ipOffset, portOffset);
}

/************************************************************
*Function    : opc_replaceIsaIpPort
*Action      : replace IP and port in session data
*Input       : data             data
			   len              data length
			   serverIp         server ip
			   newServerIp      new server ip
			   serverPort       server port
			   newServerPort    new server port
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_replaceIsaIpPort(unsigned char *data, unsigned short *len,
	char *serverIp, char *newServerIp,
	unsigned short serverPort, unsigned short newServerPort)
{
	int returnLen;
	char ipReplaceNum;
	char ip2ReplaceNum;
	char portReplaceNum;
	unsigned short strLen;
	unsigned short analyLen;
	char portStr[OPC_PORT_BUFF_LEN];
	unsigned short  unicodeOldIpLen;
	unsigned short  unicodeOldIpLen2;
	unsigned short  unicodeOldPortLen;
	unsigned short  unicodeNewIpLen;
	unsigned short  unicodeNewIpLen2;
	unsigned short  unicodeNewPortLen;
	char unicodeOldIp[OPC_UNICODE_IP_BUFF_LEN];
	char unicodeOldIp2[OPC_UNICODE_IP2_BUFF_LEN];
	char unicodeOldPort[OPC_UNICODE_PORT_BUFF_LEN];
	char unicodeNewIp[OPC_UNICODE_IP_BUFF_LEN];
	char unicodeNewIp2[OPC_UNICODE_IP2_BUFF_LEN];
	char unicodeNewPort[OPC_UNICODE_PORT_BUFF_LEN];
	unsigned char *analyAddr = NULL;
	unsigned char *writePos = NULL;
	unsigned short newDataLen;
	unsigned short oldDataLen;
	unsigned char *newData = NULL;
	unsigned char *oldData = NULL;

	oldData = data;
	oldDataLen = *len;

	newDataLen = 0;
	newData = SCMalloc(oldDataLen + OPC_DATA_INCREASE_LEN);
	if (NULL == newData)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, oldDataLen + OPC_DATA_INCREASE_LEN);
		return PARSER_ERROR;
	}

	/* old port: int->string, eg(65535 -> "65535"), change to unicode, after conversion, the first two bytes: xff, 0xfe */
	snprintf(portStr, OPC_PORT_BUFF_LEN, "%u", serverPort);
	strLen = (unsigned short)strlen(portStr);
	unicodeOldPortLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide(portStr, strLen, unicodeOldPort, OPC_UNICODE_PORT_BUFF_LEN - 1);

	/* new port: int->string, eg(65535 -> "65535"), change to unicode, after conversion, the first two bytes: xff, 0xfe */
	snprintf(portStr, OPC_PORT_BUFF_LEN, "%u", newServerPort);
	strLen = (unsigned short)strlen(portStr);
	unicodeNewPortLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide(portStr, strLen, unicodeNewPort, OPC_UNICODE_PORT_BUFF_LEN - 1);

	/* old ip: change to unicode, after conversion, the first two bytes: xff, 0xfe */
	strLen = (unsigned short)strlen(serverIp);
	unicodeOldIpLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide((char *)serverIp, strLen, unicodeOldIp, OPC_UNICODE_IP_BUFF_LEN - 1);

	/* old ip: change to unicode2, after conversion, the first two bytes: xff, 0xfe */
	if (PARSER_OK != opc_ip2ToUnicode(serverIp, unicodeOldIp2, OPC_UNICODE_IP2_BUFF_LEN - 1, &unicodeOldIpLen2))
	{
		SCFree(newData);
		newData = NULL;
		return PARSER_ERROR;
	}

	/* new ip: change to unicode, after conversion, the first two bytes: xff, 0xfe */
	strLen = (unsigned short)strlen(newServerIp);
	unicodeNewIpLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide((char *)newServerIp, strLen, unicodeNewIp, OPC_UNICODE_IP_BUFF_LEN - 1);

	/* new ip: change to unicode2, after conversion, the first two bytes: xff, 0xfe */
	if (PARSER_OK != opc_ip2ToUnicode(newServerIp, unicodeNewIp2, OPC_UNICODE_IP2_BUFF_LEN - 1, &unicodeNewIpLen2))
	{
		SCFree(newData);
		newData = NULL;
		return PARSER_ERROR;
	}

	ipReplaceNum = 0;
	ip2ReplaceNum = 0;
	portReplaceNum = 0;
	writePos = newData;
	if (NULL != (analyAddr = memnmem(oldData, oldDataLen, g_opcDataSign, OPC_DATA_SIGN_LEN)))
	{
		/* Write data in front of VMOPC */
		strLen = analyAddr - oldData;
		memcpy(writePos, oldData, strLen);
		writePos += strLen;
		newDataLen += strLen;
		oldData = analyAddr;
		oldDataLen -= strLen;
		analyLen = oldDataLen;

		while (0 < analyLen)
		{
			if (*analyAddr == (unsigned char)unicodeOldIp[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldIp, unicodeOldIpLen))
				{
					/* Replace unicode ip */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos, &newDataLen, &analyLen,
						unicodeOldIpLen, (unsigned char *)unicodeNewIp, unicodeNewIpLen);
					ipReplaceNum++;
					continue;
				}
			}
			else if (*analyAddr == (unsigned char)unicodeOldIp2[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldIp2, unicodeOldIpLen2))
				{
					/* Replace unicode ip2 */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos, &newDataLen, &analyLen,
						unicodeOldIpLen2, (unsigned char *)unicodeNewIp2, unicodeNewIpLen2);
					ip2ReplaceNum++;
					continue;
				}
			}
			else if (*analyAddr == unicodeOldPort[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldPort, unicodeOldPortLen))
				{
					/* Replace port */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos,
						&newDataLen, &analyLen, unicodeOldPortLen,
						(unsigned char *)unicodeNewPort,
						unicodeNewPortLen);
					portReplaceNum++;
					continue;
				}
			}

			analyAddr++;
			analyLen--;
		}
	}

	if (0 < oldDataLen)
	{
		memcpy(writePos, oldData, oldDataLen);
		newDataLen += oldDataLen;
	}

	memcpy(data, newData, newDataLen);

	if ((unicodeOldIpLen != unicodeNewIpLen)
		|| (unicodeOldIpLen2 != unicodeNewIpLen2)
		|| (unicodeOldPortLen != unicodeNewPortLen))
	{
		returnLen = opc_updateIsaLenInfo(data, *len, newDataLen,
			((int)(unicodeNewIpLen - unicodeOldIpLen) * ipReplaceNum
				+ (int)(unicodeNewIpLen2 - unicodeOldIpLen2) * ip2ReplaceNum) / 2,
				(int)(portReplaceNum * (unicodeNewPortLen - unicodeOldPortLen)));
		if (returnLen < 0)
		{
			newDataLen -= (unsigned short)(returnLen * (-1));
		}
		else
		{
			newDataLen += (unsigned short)returnLen;
		}
		*len = newDataLen;
	}

	SCFree(newData);
	newData = NULL;

	return PARSER_OK;
}

/************************************************************
*Function    : opc_updataIorUnused
*Action      : end zone processing
*Input       : data     data
			   len      data length
			   offset   offset
*Output      : null
*Return      : returnLen    increase or decrease length
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_updataIorUnused(unsigned char *data, unsigned short len, int offset)
{
	int returnLen;
	unsigned int ipPortGapCount;
	unsigned int gapCount32;
	unsigned short gapCount16;
	unsigned short numEntries;
	unsigned short moveOffset;
	unsigned short leftLen;
	unsigned char *leftAddr = NULL;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;

	returnLen = 0;
	numEntries = 0;

	if (0 != offset)
	{
		if (0 > offset)
		{
			ipPortGapCount = (unsigned int)(offset * (-1));
		}
		else
		{
			ipPortGapCount = (unsigned int)offset;
		}

		if (0 != ((ipPortGapCount / 2) % 2))
		{
			opcHead = (OPC_HEAD *)data;

			/* Get SecurityOffset value */
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				numEntries = opc_getLittleEndianU16(*(unsigned short *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8));
			}
			else
			{
				numEntries = opc_getBigEndianU16(*(unsigned short *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8));
			}

			/* Calculated update length */
			gapCount16 = htons(2);
			gapCount32 = htonl(2);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
				gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
			}

			/* Judge end area reservation increase or decrease */
			if (0 != (numEntries % 2))
			{
				/* Increase */

				/* Update total length */
				opcHead->fragLength += gapCount16;

				/* Update hit length */
				opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
				opcResp->allocHint += gapCount32;

				/* Update data location */
				moveOffset = sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8 + (numEntries * 2);
				leftLen = len - moveOffset;
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, data + moveOffset, leftLen);
				memset(data + moveOffset, 0, 2);
				memcpy(data + moveOffset + 2, leftAddr, leftLen);
				returnLen = 2;
			}
			else
			{
				/* Reduce */

				/* Update total length */
				opcHead->fragLength -= gapCount16;

				/* Update hit length */
				opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
				opcResp->allocHint -= gapCount32;

				/* Update data location */
				moveOffset = sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8 + (numEntries * 2) + 2;
				leftLen = len - moveOffset;
				leftAddr = (unsigned char *)SCMalloc(leftLen);
				if (NULL == leftAddr)
				{
					SCLogError("[%s:%d]SCMalloc failed, size(%u)", __func__, __LINE__, leftLen);
					return returnLen;
				}
				memcpy(leftAddr, data + moveOffset, leftLen);
				memcpy(data + moveOffset - 2, leftAddr, leftLen);
				returnLen = -2;
			}
			SCFree(leftAddr);
			leftAddr = NULL;
		}
	}

	SCLogInfo("[%s:%d]update ior unused, returnLen:%d", __func__, __LINE__, returnLen);

	return returnLen;
}

/************************************************************
*Function    : opc_updateIorIpPortLenInfo
*Action      : update IOXIDResolver response data length information
*Input       : data     data
			   len      data length
			   newLen   new length
			   offset   offset
*Output      : null
*Return      : returnLen    increase or decrease length
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_updateIorIpPortLenInfo(unsigned char *data, unsigned short len, unsigned short newLen, int offset)
{
	unsigned short ipPortGapCount16;
	unsigned int ipPortGapCount32;
	unsigned int gapCount32;
	unsigned short gapCount16;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;

	opcHead = (OPC_HEAD *)data;

	SCLogInfo("[%s:%d]IOR(IP+Port), len:%u  newLen:%u offset:%d", __func__, __LINE__, len, newLen, offset);

	if (len > newLen)
	{
		/* Reduce */
		gapCount16 = (unsigned short)(len - newLen);
		gapCount32 = (unsigned int)(len - newLen);

		gapCount16 = htons(gapCount16);
		gapCount32 = htonl(gapCount32);
		if (opcHead->dataRepresentation[0] & 0x10)
		{
			/* Small end */
			gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
			gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
		}

		/* Update total length */
		opcHead->fragLength -= gapCount16;

		/* Update hit length */
		opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
		opcResp->allocHint -= gapCount32;
	}
	else
	{
		/* Increase */
		gapCount16 = (unsigned short)(newLen - len);
		gapCount32 = (unsigned int)(newLen - len);

		gapCount16 = htons(gapCount16);
		gapCount32 = htonl(gapCount32);
		if (opcHead->dataRepresentation[0] & 0x10)
		{
			/* Small end */
			gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
			gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
		}

		/* Update total length */
		opcHead->fragLength += gapCount16;

		/* Update hit length */
		opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
		opcResp->allocHint += gapCount32;
	}

	if (0 != offset)
	{
		if (0 > offset)
		{
			ipPortGapCount16 = (unsigned short)(offset * (-1));
			ipPortGapCount32 = (unsigned int)(offset * (-1));
			ipPortGapCount16 = (ipPortGapCount16 / 2);
			ipPortGapCount32 = (ipPortGapCount32 / 2);
			ipPortGapCount16 = htons(ipPortGapCount16);
			ipPortGapCount32 = htonl(ipPortGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipPortGapCount16 = BYTE_SEQ_SWITCH_16(ipPortGapCount16);
				ipPortGapCount32 = BYTE_SEQ_SWITCH_32(ipPortGapCount32);
			}

			*(unsigned int *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 4) -= ipPortGapCount32;
			*(unsigned short *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8) -= ipPortGapCount16;
			*(unsigned short *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8 + 2) -= ipPortGapCount16;
		}
		else
		{
			ipPortGapCount16 = (unsigned int)offset;
			ipPortGapCount32 = (unsigned int)offset;
			ipPortGapCount16 = (ipPortGapCount16 / 2);
			ipPortGapCount32 = (ipPortGapCount32 / 2);
			ipPortGapCount16 = htons(ipPortGapCount16);
			ipPortGapCount32 = htonl(ipPortGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipPortGapCount16 = BYTE_SEQ_SWITCH_16(ipPortGapCount16);
				ipPortGapCount32 = BYTE_SEQ_SWITCH_32(ipPortGapCount32);
			}

			*(unsigned int *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 4) += ipPortGapCount32;
			*(unsigned short *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8) += ipPortGapCount16;
			*(unsigned short *)(data + sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE) + 8 + 2) += ipPortGapCount16;
		}
	}

	/* End zone processing */
	return opc_updataIorUnused(data, newLen, offset);
}

/************************************************************
*Function    : opc_replaceIorIpPort
*Action      : replace IP and port in session data
*Input       : data             data
			   len              data length
			   serverIp         server ip
			   newServerIp      new server ip
			   serverPort       server port
			   newServerPort    new server port
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_replaceIorIpPort(unsigned char *data, unsigned short *len,
	char *serverIp, char *newServerIp,
	unsigned short serverPort, unsigned short newServerPort)
{
	int returnLen;
	char ipReplaceNum;
	char ip2ReplaceNum;
	char portReplaceNum;
	unsigned short strLen;
	unsigned short analyLen;
	char portStr[OPC_PORT_BUFF_LEN];
	unsigned short  unicodeOldIpLen;
	unsigned short  unicodeOldIpLen2;
	unsigned short  unicodeOldPortLen;
	unsigned short  unicodeNewIpLen;
	unsigned short  unicodeNewIpLen2;
	unsigned short  unicodeNewPortLen;
	char unicodeOldIp[OPC_UNICODE_IP_BUFF_LEN];
	char unicodeOldIp2[OPC_UNICODE_IP2_BUFF_LEN];
	char unicodeOldPort[OPC_UNICODE_PORT_BUFF_LEN];
	char unicodeNewIp[OPC_UNICODE_IP_BUFF_LEN];
	char unicodeNewIp2[OPC_UNICODE_IP2_BUFF_LEN];
	char unicodeNewPort[OPC_UNICODE_PORT_BUFF_LEN];
	unsigned char *analyAddr = NULL;
	unsigned char *writePos = NULL;
	unsigned short newDataLen;
	unsigned short oldDataLen;
	unsigned char *newData = NULL;
	unsigned char *oldData = NULL;

	oldData = data;
	oldDataLen = *len;

	newDataLen = 0;
	newData = SCMalloc(oldDataLen + OPC_DATA_INCREASE_LEN);
	if (NULL == newData)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, oldDataLen + OPC_DATA_INCREASE_LEN);
		return PARSER_ERROR;
	}

	/* old port: int->string, eg(65535 -> "65535"), change to unicode, after conversion, the first two bytes: xff, 0xfe */
	snprintf(portStr, OPC_PORT_BUFF_LEN, "%u", serverPort);
	strLen = (unsigned short)strlen(portStr);
	unicodeOldPortLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide(portStr, strLen, unicodeOldPort, OPC_UNICODE_PORT_BUFF_LEN - 1);

	/* new port: int->string, eg(65535 -> "65535"), change to unicode, after conversion, the first two bytes: xff, 0xfe */
	snprintf(portStr, OPC_PORT_BUFF_LEN, "%u", newServerPort);
	strLen = (unsigned short)strlen(portStr);
	unicodeNewPortLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide(portStr, strLen, unicodeNewPort, OPC_UNICODE_PORT_BUFF_LEN - 1);

	/* old ip: change to unicode, after conversion, the first two bytes: xff, 0xfe */
	strLen = (unsigned short)strlen(serverIp);
	unicodeOldIpLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide((char *)serverIp, strLen, unicodeOldIp, OPC_UNICODE_IP_BUFF_LEN - 1);

	/* old ip: change to unicode2, after conversion, the first two bytes: xff, 0xfe */
	if (PARSER_OK != opc_ip2ToUnicode(serverIp, unicodeOldIp2, OPC_UNICODE_IP2_BUFF_LEN - 1, &unicodeOldIpLen2))
	{
		SCFree(newData);
		newData = NULL;
		return PARSER_ERROR;
	}

	/* new ip: change to unicode, after conversion, the first two bytes: xff, 0xfe */
	strLen = (unsigned short)strlen(newServerIp);
	unicodeNewIpLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide((char *)newServerIp, strLen, unicodeNewIp, OPC_UNICODE_IP_BUFF_LEN - 1);

	/* new ip: change to unicode2, after conversion, the first two bytes: xff, 0xfe */
	if (PARSER_OK != opc_ip2ToUnicode(newServerIp, unicodeNewIp2, OPC_UNICODE_IP2_BUFF_LEN - 1, &unicodeNewIpLen2))
	{
		SCFree(newData);
		newData = NULL;
		return PARSER_ERROR;
	}

	ipReplaceNum = 0;
	ip2ReplaceNum = 0;
	portReplaceNum = 0;
	writePos = newData;
	if (NULL != (analyAddr = memnmem(oldData, oldDataLen, g_opcDataSign, OPC_DATA_SIGN_LEN)))
	{
		/* Write data in front of VMOPC */
		strLen = analyAddr - oldData;
		memcpy(writePos, oldData, strLen);
		writePos += strLen;
		newDataLen += strLen;
		oldData = analyAddr;
		oldDataLen -= strLen;
		analyLen = oldDataLen;

		while (0 < analyLen)
		{
			if (*analyAddr == (unsigned char)unicodeOldIp[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldIp, unicodeOldIpLen))
				{
					/* Replace unicode ip */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos,
						&newDataLen, &analyLen, unicodeOldIpLen,
						(unsigned char *)unicodeNewIp, unicodeNewIpLen);
					ipReplaceNum++;
					continue;
				}
			}
			else if (*analyAddr == (unsigned char)unicodeOldIp2[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldIp2, unicodeOldIpLen2))
				{
					/* Replace unicode ip2 */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos,
						&newDataLen, &analyLen, unicodeOldIpLen2,
						(unsigned char *)unicodeNewIp2, unicodeNewIpLen2);
					ip2ReplaceNum++;
					continue;
				}
			}
			else if (*analyAddr == unicodeOldPort[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldPort, unicodeOldPortLen))
				{
					/* Replace port */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos,
						&newDataLen, &analyLen, unicodeOldPortLen,
						(unsigned char *)unicodeNewPort,
						unicodeNewPortLen);
					portReplaceNum++;
					continue;
				}
			}

			analyAddr++;
			analyLen--;
		}
	}

	if (0 < oldDataLen)
	{
		memcpy(writePos, oldData, oldDataLen);
		newDataLen += oldDataLen;
	}

	memcpy(data, newData, newDataLen);
	if ((unicodeOldIpLen != unicodeNewIpLen)
		|| (unicodeOldIpLen2 != unicodeNewIpLen2)
		|| (unicodeOldPortLen != unicodeNewPortLen))
	{
		returnLen = opc_updateIorIpPortLenInfo(data, *len, newDataLen, (int)((unicodeNewIpLen * ipReplaceNum)
			+ (unicodeNewIpLen2 * ip2ReplaceNum)
			+ (unicodeNewPortLen * portReplaceNum))
			- (int)((unicodeOldIpLen * ipReplaceNum)
				+ (unicodeOldIpLen2 * ip2ReplaceNum)
				+ (unicodeOldPortLen * portReplaceNum)));
		if (returnLen < 0)
		{
			newDataLen -= (unsigned short)(returnLen * (-1));
		}
		else
		{
			newDataLen += (unsigned short)returnLen;
		}
		*len = newDataLen;
	}

	SCFree(newData);
	newData = NULL;

	return PARSER_OK;
}

/************************************************************
*Function    : opc_updateIorIpLenInfo
*Action      : update IOXIDResolver response data length information
*Input       : data     data
			   len      data length
			   newLen   new length
			   offset   offset
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static void opc_updateIorIpLenInfo(unsigned char *data, unsigned short len, unsigned short newLen, int offset)
{
	unsigned int offLen;
	unsigned short ipGapCount16;
	unsigned int ipGapCount32;
	unsigned int gapCount32;
	unsigned short gapCount16;
	OPC_HEAD *opcHead = NULL;
	OPC_RESPONSE *opcResp = NULL;

	opcHead = (OPC_HEAD *)data;

	SCLogInfo("[%s:%d]IOR(IP), len:%u  newLen:%u offset:%d\n", __func__, __LINE__, len, newLen, offset);

	if (len > newLen)
	{
		/* Reduce */
		gapCount16 = (unsigned short)(len - newLen);
		gapCount32 = (unsigned int)(len - newLen);

		gapCount16 = htons(gapCount16);
		gapCount32 = htonl(gapCount32);
		if (opcHead->dataRepresentation[0] & 0x10)
		{
			/* Small end */
			gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
			gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
		}

		/* Update total length */
		opcHead->fragLength -= gapCount16;

		/* Update hit length */
		opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
		opcResp->allocHint -= gapCount32;
	}
	else
	{
		/* Increase */
		gapCount16 = (unsigned short)(newLen - len);
		gapCount32 = (unsigned int)(newLen - len);

		gapCount16 = htons(gapCount16);
		gapCount32 = htonl(gapCount32);
		if (opcHead->dataRepresentation[0] & 0x10)
		{
			/* Small end */
			gapCount16 = BYTE_SEQ_SWITCH_16(gapCount16);
			gapCount32 = BYTE_SEQ_SWITCH_32(gapCount32);
		}

		/* Update total length */
		opcHead->fragLength += gapCount16;

		/* Update hit length */
		opcResp = (OPC_RESPONSE *)(data + OPC_HEAD_LEN);
		opcResp->allocHint += gapCount32;
	}

	if (0 != offset)
	{
		if (0 > offset)
		{
			ipGapCount16 = (unsigned short)(offset * (-1));
			ipGapCount32 = (unsigned int)(offset * (-1));
			ipGapCount16 = (ipGapCount16 / 2);
			ipGapCount32 = (ipGapCount32 / 2);
			ipGapCount16 = htons(ipGapCount16);
			ipGapCount32 = htonl(ipGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipGapCount16 = BYTE_SEQ_SWITCH_16(ipGapCount16);
				ipGapCount32 = BYTE_SEQ_SWITCH_32(ipGapCount32);
			}

			offLen = sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE);
			data += offLen;

			*(unsigned int *)(data + 8) -= ipGapCount32;
			*(unsigned short *)(data + 12) -= ipGapCount16;
			*(unsigned short *)(data + 12 + 2) -= ipGapCount16;
		}
		else
		{
			ipGapCount16 = (unsigned short)offset;
			ipGapCount32 = (unsigned int)offset;
			ipGapCount16 = (ipGapCount16 / 2);
			ipGapCount32 = (ipGapCount32 / 2);
			ipGapCount16 = htons(ipGapCount16);
			ipGapCount32 = htonl(ipGapCount32);
			if (opcHead->dataRepresentation[0] & 0x10)
			{
				/* Small end */
				ipGapCount16 = BYTE_SEQ_SWITCH_16(ipGapCount16);
				ipGapCount32 = BYTE_SEQ_SWITCH_32(ipGapCount32);
			}

			offLen = sizeof(OPC_HEAD) + sizeof(OPC_RESPONSE);
			data += offLen;

			*(unsigned int *)(data + 8) += ipGapCount32;
			*(unsigned short *)(data + 12) += ipGapCount16;
			*(unsigned short *)(data + 12 + 2) += ipGapCount16;
		}
	}

	return;
}

/************************************************************
*Function    : opc_replaceDataIp
*Action      : replace IP in session data
*Input       : data         data
			   len          data len
			   serverIp     server ip
			   newServerIp  new server ip
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
int opc_replaceDataIp(unsigned char *data, unsigned short *len, char *serverIp, char *newServerIp)
{
	char ipReplaceNum;
	char ip2ReplaceNum;
	unsigned short strLen;
	unsigned short analyLen;
	unsigned short  unicodeOldIpLen;
	unsigned short  unicodeOldIpLen2;
	unsigned short  unicodeNewIpLen;
	unsigned short  unicodeNewIpLen2;
	char unicodeOldIp[OPC_UNICODE_IP_BUFF_LEN];
	char unicodeOldIp2[OPC_UNICODE_IP2_BUFF_LEN];
	char unicodeNewIp[OPC_UNICODE_IP_BUFF_LEN];
	char unicodeNewIp2[OPC_UNICODE_IP2_BUFF_LEN];
	unsigned char *analyAddr = NULL;
	unsigned char *writePos = NULL;
	unsigned short newDataLen;
	unsigned short oldDataLen;
	unsigned char *newData = NULL;
	unsigned char *oldData = NULL;

	oldData = data;
	oldDataLen = *len;

	newDataLen = 0;
	newData = SCMalloc(oldDataLen + OPC_DATA_INCREASE_LEN);
	if (NULL == newData)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, oldDataLen + OPC_DATA_INCREASE_LEN);
		return PARSER_ERROR;
	}

	/* old ip: change to unicode, after conversion, the first two bytes: xff, 0xfe */
	strLen = (unsigned short)strlen(serverIp);
	unicodeOldIpLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide((char *)serverIp, strLen, unicodeOldIp, OPC_UNICODE_IP_BUFF_LEN - 1);

	/* old ip: change to unicode2, after conversion, the first two bytes: xff, 0xfe */
	if (PARSER_OK != opc_ip2ToUnicode(serverIp, unicodeOldIp2, OPC_UNICODE_IP2_BUFF_LEN - 1, &unicodeOldIpLen2))
	{
		SCFree(newData);
		newData = NULL;
		return PARSER_ERROR;
	}

	/* new ip: change to unicode, after conversion, the first two bytes: xff, 0xfe */
	strLen = (unsigned short)strlen(newServerIp);
	unicodeNewIpLen = strLen * OPC_CHAR_WIDE_SIZE;
	(void)char2Wide((char *)newServerIp, strLen, unicodeNewIp, OPC_UNICODE_IP_BUFF_LEN - 1);

	/* new ip: change to unicode2, after conversion, the first two bytes: xff, 0xfe */
	if (PARSER_OK != opc_ip2ToUnicode(newServerIp, unicodeNewIp2, OPC_UNICODE_IP2_BUFF_LEN - 1, &unicodeNewIpLen2))
	{
		SCFree(newData);
		newData = NULL;
		return PARSER_ERROR;
	}

	ipReplaceNum = 0;
	ip2ReplaceNum = 0;
	writePos = newData;
	if (NULL != (analyAddr = memnmem(oldData, oldDataLen, g_opcDataSign, OPC_DATA_SIGN_LEN)))
	{
		/* Write data in front of VMOPC */
		strLen = analyAddr - oldData;
		memcpy(writePos, oldData, strLen);
		writePos += strLen;
		newDataLen += strLen;
		oldData = analyAddr;
		oldDataLen -= strLen;
		analyLen = oldDataLen;

		while (0 < analyLen)
		{
			if (*analyAddr == (unsigned char)unicodeOldIp[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldIp, unicodeOldIpLen))
				{
					/* Replace ip */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos, &newDataLen, &analyLen,
						unicodeOldIpLen, (unsigned char *)unicodeNewIp, unicodeNewIpLen);
					ipReplaceNum++;
					continue;
				}
			}
			else if (*analyAddr == (unsigned char)unicodeOldIp2[0])
			{
				if (0 == memcmp(analyAddr, (unsigned char *)unicodeOldIp2, unicodeOldIpLen2))
				{
					/* Replace ip2 */
					opc_replaceParse(&analyAddr, &oldData, &oldDataLen, &writePos, &newDataLen, &analyLen,
						unicodeOldIpLen2, (unsigned char *)unicodeNewIp2, unicodeNewIpLen2);
					ip2ReplaceNum++;
					continue;
				}
			}

			analyAddr++;
			analyLen--;
		}
	}

	if (0 < oldDataLen)
	{
		memcpy(writePos, oldData, oldDataLen);
		newDataLen += oldDataLen;
	}

	memcpy(data, newData, newDataLen);
	if (*len != newDataLen)
	{
		opc_updateIorIpLenInfo(data, *len, newDataLen, (int)(((unicodeNewIpLen * ipReplaceNum)
			+ (unicodeNewIpLen2 * ip2ReplaceNum))
			- ((unicodeOldIpLen * ipReplaceNum)
				+ (unicodeOldIpLen2 * ip2ReplaceNum))));
		*len = newDataLen;
	}

	SCFree(newData);
	newData = NULL;

	return PARSER_OK;
}

/************************************************************
*Function    : opc_handleEventRspbufSession
*Action      : analysis response session data
*Input       : hdr          packet processing header information
			   session      session
			   fragLength   data packet length information
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_handleEventRspbufSession(struct filter_header *hdr, OPC_SESSION *session, unsigned short fragLength)
{
	unsigned short dynamicPort;
	unsigned short serverPort;
	unsigned char *content = NULL;

	content = SCMalloc(fragLength + OPC_DATA_INCREASE_LEN);
	if (NULL == content)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, fragLength + OPC_DATA_INCREASE_LEN);
		return PARSER_ERROR;
	}

	if (-1 == evbuffer_remove(session->rspBuf, content, fragLength))
	{
		SCFree(content);
		content = NULL;
		SCLogError("[%s:%d]evbuffer_remove failed, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}

	if (0x0004 == session->opnum)
	{
		if (ISYSTEMACTIVATOR_ID == session->interfaceId)
		{
			/* ISystemActivator */
			if (PARSER_OK == opc_getIsaPort(content, fragLength, &serverPort))
			{
				//SCLogInfo("[%s:%d]outer, get port(%u), sessionid(%u)", __func__, __LINE__, serverPort, hdr->sessionid);

				if (0 != opc_createDataSvr(hdr, serverPort, NULL, NULL, &dynamicPort))
				{
					SCFree(content);
					content = NULL;
					SCLogError("[%s:%d]outer, create new port rule failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
					return PARSER_ERROR;
				}

				if (ROUTE_MAPPED == hdr->routetype)
				{
					/* Replace ip and prot */
					SCLogInfo("[%s:%d]outer ISystemActivator replace, ip(%s --> %s), port(%u --> %u), sessionid(%u)",
						__func__, __LINE__, hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort, hdr->sessionid);

					if (PARSER_OK != opc_replaceIsaIpPort(content, &fragLength,
						hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort))
					{
						SCFree(content);
						content = NULL;
						return PARSER_ERROR;
					}
				}
				else
				{
					SCLogInfo("[%s:%d]route type(%d) is not mapped, not to change response data, sessionid(%u)",
						__func__, __LINE__, hdr->routetype, hdr->sessionid);
				}
			}
		}
		else if (IOXIDRESOLVER_ID == session->interfaceId)
		{
			/* IOXIDResolver */
			if (PARSER_OK == opc_getIsaPort(content, fragLength, &serverPort))
			{
				//SCLogInfo("[%s:%d]outer, get port(%u), sessionid(%u)", __func__, __LINE__, serverPort, hdr->sessionid);

				if (0 != opc_createDataSvr(hdr, serverPort, NULL, NULL, &dynamicPort))
				{
					SCFree(content);
					content = NULL;
					SCLogError("[%s:%d]outer, create new port rule failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
					return PARSER_ERROR;
				}

				if (ROUTE_MAPPED == hdr->routetype)
				{
					/* Replace ip and prot */
					SCLogInfo("[%s:%d]outer IOXIDResolver replace, ip(%s --> %s), port(%u --> %u), sessionid(%u)",
						__func__, __LINE__, hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort, hdr->sessionid);

					if (PARSER_OK != opc_replaceIorIpPort(content, &fragLength,
						hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort))
					{
						SCFree(content);
						content = NULL;
						return PARSER_ERROR;
					}
				}
				else
				{
					SCLogInfo("[%s:%d]route type(%d) is not mapped, not to change response data, sessionid(%u)",
						__func__, __LINE__, hdr->routetype, hdr->sessionid);
				}
			}
		}
	}
	else if (0x0005 == session->opnum)
	{
		if (IOXIDRESOLVER_ID == session->interfaceId)
		{
			/* IOXIDResolver */
			if (ROUTE_MAPPED == hdr->routetype)
			{
				/* Replace ip */
				SCLogInfo("[%s:%d]outer IOXIDResolver replace, ip(%s --> %s), sessionid(%u)",
					__func__, __LINE__, hdr->svr->dstip, hdr->svr->localip, hdr->sessionid);

				if (PARSER_OK != opc_replaceDataIp(content, &fragLength, hdr->svr->dstip, hdr->svr->localip))
				{
					SCFree(content);
					content = NULL;
					return PARSER_ERROR;
				}
			}
			else
			{
				SCLogInfo("[%s:%d]route type(%d) is not mapped, not to change response data, sessionid(%u)",
					__func__, __LINE__, hdr->routetype, hdr->sessionid);
			}
		}
	}

	//SCLogInfo("[%s:%d]sent to req, len(%u), sessionid(%u)", __func__, __LINE__, fragLength, hdr->sessionid);
	if (0 != buffer_sendtoreq(hdr, content, fragLength))
	{
		SCFree(content);
		content = NULL;
		SCLogError("[%s:%d]req callback failed, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}

	SCFree(content);
	content = NULL;
	return PARSER_OK;
}

/************************************************************
*Function    : opc_updateCltEventRspbufData
*Action      : check the full session in rspbuf
*Input       : hdr          packet processing header information
			   session      session obj
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.23
*Instruction : null
************************************************************/
static int opc_updateCltEventRspbufData(struct filter_header *hdr, OPC_SESSION *session)
{
	ev_ssize_t ret;
	size_t eventBufLen;
	OPC_HEAD opcHead;

	while (1)
	{
		/* Get data length of client response eventbuffer */
		eventBufLen = evbuffer_get_length(session->rspBuf);
		if (0 >= eventBufLen)
		{
			break;
		}

		/* Check head data all receive */
		if (OPC_HEAD_LEN >= eventBufLen)
		{
			break;
		}

		/* Get opc head */
		ret = evbuffer_copyout(session->rspBuf, (void *)&opcHead, sizeof(OPC_HEAD));
		if (-1 == ret)
		{
			SCLogError("[%s:%d]copy data from rsp buff failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
		opc_convHead(&opcHead);

		/* Check head valid */
		if ((0x05 != opcHead.version) || ((0x00 != opcHead.version_minor) && (0x01 != opcHead.version_minor)))
		{
			SCLogError("[%s:%d]invalid opc head, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		/* Check body data all receive */
		if (eventBufLen < opcHead.fragLength)
		{
			break;
		}

		/* Update this whole session */
		if (0x02 == opcHead.packetType)
		{
			/* Response(2) */
			if (session->callId == opcHead.callId)
			{
				if (PARSER_OK != opc_handleEventRspbufSession(hdr, session, opcHead.fragLength))
				{
					return PARSER_ERROR;
				}
				continue;
			}
		}

		/* send this session to req */
		if (0 != evbuffer_sendtoreq(hdr, session->rspBuf, opcHead.fragLength))
		{
			SCLogError("[%s:%d]send session buffer data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opc_analyRspbufData
*Action      : response packet analysis, modification, send
*Input       : hdr          packet processing header information
			   session      session
			   buff         buffer
			   fragLength   data packet length information
*Output      : null
*Return      : PARSER_OK    success
			   PARSER_ERROR failure
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_handleRspbufSession(struct filter_header *hdr, OPC_SESSION *session, const void *buff, unsigned short fragLength)
{
	unsigned short dynamicPort;
	unsigned short serverPort;
	unsigned char *content = NULL;

	content = SCMalloc(fragLength + OPC_DATA_INCREASE_LEN);
	if (NULL == content)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, fragLength + OPC_DATA_INCREASE_LEN);
		return PARSER_ERROR;
	}

	memcpy(content, buff, fragLength);

	if (0x0004 == session->opnum)
	{
		if (ISYSTEMACTIVATOR_ID == session->interfaceId)
		{
			/* ISystemActivator */
			if (PARSER_OK == opc_getIsaPort(content, fragLength, &serverPort))
			{
				//SCLogInfo("[%s:%d]outer, get port(%u), sessionid(%u)", __func__, __LINE__, serverPort, hdr->sessionid);

				if (0 != opc_createDataSvr(hdr, serverPort, NULL, NULL, &dynamicPort))
				{
					SCFree(content);
					content = NULL;
					SCLogError("[%s:%d]outer, create new port rule failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
					return PARSER_ERROR;
				}

				if (ROUTE_MAPPED == hdr->routetype)
				{
					/* Replace ip and prot */
					SCLogInfo("[%s:%d]outer ISystemActivator replace, ip(%s --> %s), port(%u --> %u), sessionid(%u)",
						__func__, __LINE__, hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort, hdr->sessionid);

					if (PARSER_OK != opc_replaceIsaIpPort(content, &fragLength,
						hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort))
					{
						SCFree(content);
						content = NULL;
						return PARSER_ERROR;
					}
				}
				else
				{
					SCLogInfo("[%s:%d]route type(%d) is not mapped, not to change response data, sessionid(%u)",
						__func__, __LINE__, hdr->routetype, hdr->sessionid);
				}
			}
		}
		else if (IOXIDRESOLVER_ID == session->interfaceId)
		{
			/* IOXIDResolver */
			if (PARSER_OK == opc_getIsaPort(content, fragLength, &serverPort))
			{
				//SCLogInfo("[%s:%d]outer, get port(%u), sessionid(%u)", __func__, __LINE__, serverPort, hdr->sessionid);

				if (0 != opc_createDataSvr(hdr, serverPort, NULL, NULL, &dynamicPort))
				{
					SCFree(content);
					content = NULL;
					SCLogError("[%s:%d]outer, create new port rule failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
					return PARSER_ERROR;
				}

				if (ROUTE_MAPPED == hdr->routetype)
				{
					/* Replace ip and prot */
					SCLogInfo("[%s:%d]outer IOXIDResolver replace, ip(%s --> %s), port(%u --> %u), sessionid(%u)",
						__func__, __LINE__, hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort, hdr->sessionid);

					if (PARSER_OK != opc_replaceIorIpPort(content, &fragLength,
						hdr->svr->dstip, hdr->svr->localip,
						serverPort, dynamicPort))
					{
						SCFree(content);
						content = NULL;
						return PARSER_ERROR;
					}
				}
				else
				{
					SCLogInfo("[%s:%d]route type(%d) is not mapped, not to change response data, sessionid(%u)",
						__func__, __LINE__, hdr->routetype, hdr->sessionid);
				}
			}
		}
	}
	else if (0x0005 == session->opnum)
	{
		if (IOXIDRESOLVER_ID == session->interfaceId)
		{
			/* IOXIDResolver */
			if (ROUTE_MAPPED == hdr->routetype)
			{
				/* Replace ip */
				SCLogInfo("[%s:%d]outer IOXIDResolver replace, ip(%s --> %s), sessionid(%u)",
					__func__, __LINE__, hdr->svr->dstip, hdr->svr->localip, hdr->sessionid);

				if (PARSER_OK != opc_replaceDataIp(content, &fragLength, hdr->svr->dstip, hdr->svr->localip))
				{
					SCFree(content);
					content = NULL;
					return PARSER_ERROR;
				}
			}
			else
			{
				SCLogInfo("[%s:%d]route type(%d) is not mapped, not to change response data, sessionid(%u)",
					__func__, __LINE__, hdr->routetype, hdr->sessionid);
			}
		}
	}

	//SCLogInfo("[%s:%d]sent to req, len(%u), sessionid(%u)", __func__, __LINE__, fragLength, hdr->sessionid);
	if (0 != buffer_sendtoreq(hdr, content, fragLength))
	{
		SCFree(content);
		content = NULL;
		SCLogError("[%s:%d]req callback failed, sessionid(%u)", __func__, __LINE__, hdr->sessionid);
		return PARSER_ERROR;
	}

	SCFree(content);
	content = NULL;
	return PARSER_OK;
}

/************************************************************
*Function    : opc_updateCltRspbufData
*Action      : update the full session in buff
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
static int opc_updateCltRspbufData(struct filter_header *hdr, OPC_SESSION *session, const void *buff, size_t len)
{
	OPC_HEAD opcHead;

	while (1)
	{
		/* Get data length of client response buff */
		if (0 >= len)
		{
			break;
		}

		/* Check head data all receive */
		if (OPC_HEAD_LEN >= len)
		{
			if (0 != evbuffer_add(session->rspBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
			break;
		}

		/* Get opc head */
		memcpy((void *)&opcHead, buff, sizeof(OPC_HEAD));
		opc_convHead(&opcHead);

		/* Check head valid */
		if ((0x05 != opcHead.version) || ((0x00 != opcHead.version_minor) && (0x01 != opcHead.version_minor)))
		{
			SCLogError("[%s:%d]invalid opc head, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}

		/* Check body data all receive */
		if (len < opcHead.fragLength)
		{
			if (0 != evbuffer_add(session->rspBuf, buff, len))
			{
				SCLogError("[%s:%d]add data to session buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}
			break;
		}

		/* Check this whole session */
		if (0x02 == opcHead.packetType)
		{
			/* Response(2) */
			if (session->callId == opcHead.callId)
			{
				if (PARSER_OK != opc_handleRspbufSession(hdr, session, buff, opcHead.fragLength))
				{
					return PARSER_ERROR;
				}

				buff += opcHead.fragLength;
				len -= opcHead.fragLength;
				continue;
			}
		}

		/* send this session to req */
		if (0 != buffer_sendtoreq(hdr, buff, opcHead.fragLength))
		{
			SCLogError("[%s:%d]send session buffer data to req failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
			return PARSER_ERROR;
		}
		buff += opcHead.fragLength;
		len -= opcHead.fragLength;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : opc_handleClientRsp
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
static int opc_handleClientRsp(struct filter_header *hdr, OPC_SESSION *session, ForwardObject *obj)
{
	if (0 < evbuffer_get_length(session->rspBuf))
	{
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Add data to response eventbuffer */
			if (0 != evbuffer_add(session->rspBuf, obj->buffdata.data, obj->buffdata.len))
			{
				SCLogError("[%s:%d]add data to session rsp buffer failed, ssid(%u)", __func__, __LINE__, hdr->sessionid);
				return PARSER_ERROR;
			}

		}

		/* Client handle: rsp buffer and this data */
		if (PARSER_OK != opc_updateCltEventRspbufData(hdr, session))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		if ((NULL != obj->buffdata.data) && (0 < obj->buffdata.len))
		{
			/* Client handle: this data */
			if (PARSER_OK != opc_updateCltRspbufData(hdr, session, obj->buffdata.data, obj->buffdata.len))
			{
				return PARSER_ERROR;
			}
		}
	}

	return PARSER_OK;
}
#endif

#if GAP_DESC("server response message")
/************************************************************
*Function    : opc_handleClientRsp
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
static int opc_handleServerRsp(struct filter_header *hdr, OPC_SESSION *session, ForwardObject *obj)
{
	/* Send response eventbuffer */
	if (0 < evbuffer_get_length(session->rspBuf))
	{
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
*Function    : opc_freeObjMemory
*Action      : free opc config object memory
*Input       : opcConfig    opc config object
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.6.20
*Instruction : null
************************************************************/
static void opc_freeObjMemory(OPC_CONFIG_INFO *opcConfig, int isFreeJstr)
{
	if (opcConfig->groupName)
	{
		SCFree(opcConfig->groupName);
	}

	if (isFreeJstr)
	{
		if (opcConfig->jstr)
		{
			XFREE(MTYPE_TMP, opcConfig->jstr);
		}
	}

	SCFree(opcConfig);
	return;
}

/************************************************************
*Function    : opc_getDataMode
*Action      : get opc data mode by group name
*Input       : groupName group name
*Output      : null
*Return      : OPC DATA MODE
*Author      : liuzongquan(000932)
*Date        : 2017.6.20
*Instruction : null
************************************************************/
OPC_DATA_MODE opc_getDataMode(char *groupName)
{
	OPC_CONFIG_INFO *oldConfig = NULL;

	SCLogInfo("[%s:%d]groupName(%s)", __func__, __LINE__, groupName);
	oldConfig = (OPC_CONFIG_INFO *)get_protocol_rule(groupName, SVR_ID_OPC);
	if (oldConfig)
	{
		if (0 == oldConfig->valid)
		{
			return OPC_DATA_RW;
		}

		return ((oldConfig->mode) ? OPC_DATA_RW : OPC_DATA_R);
	}

	SCLogWarning("[%s:%d]get_protocol_rule faile, groupName(%s)", __func__, __LINE__, groupName);
	return OPC_DATA_RW;
}

void opc_delRule(void *opcRule)
{
	OPC_CONFIG_INFO *oldConfig = NULL;

	if (opcRule)
	{
		oldConfig = (OPC_CONFIG_INFO *)opcRule;
		list_del(&(oldConfig->topList));
		opc_freeObjMemory(oldConfig, PARSER_BTRUE);
	}
	return;
}

void opc_delConfig(const char *groupName)
{
	OPC_CONFIG_INFO *oldConfig = NULL;

	oldConfig = (OPC_CONFIG_INFO *)get_protocol_rule(groupName, SVR_ID_OPC);
	if (oldConfig)
	{
		if (0 != set_protocol_rule(groupName, SVR_ID_OPC, NULL))
		{
			SCLogError("[%s:%d]set protocol rule to group failed, group name(%s)", __func__, __LINE__, groupName);
			return;
		}

		list_del(&(oldConfig->topList));
		opc_freeObjMemory(oldConfig, PARSER_BTRUE);
	}

	return;
}

int opc_addConfig(OPC_CONFIG_INFO *opcConfig)
{
	OPC_CONFIG_INFO *oldConfig = NULL;

	oldConfig = (OPC_CONFIG_INFO *)get_protocol_rule(opcConfig->groupName, SVR_ID_OPC);
	if (oldConfig)
	{
		oldConfig->valid = opcConfig->valid;
		oldConfig->mode = opcConfig->mode;
		XFREE(MTYPE_TMP, oldConfig->jstr);
		oldConfig->jstr = opcConfig->jstr;
		SCFree(opcConfig->groupName);
		SCFree(opcConfig);
		return PARSER_OK;
	}

	if (0 != set_protocol_rule(opcConfig->groupName, SVR_ID_OPC, (void *)opcConfig))
	{
		SCLogError("[%s:%d]set protocol rule to group failed, group name(%s)", __func__, __LINE__, opcConfig->groupName);
		opc_freeObjMemory(opcConfig, PARSER_BFALSE);
		return PARSER_ERROR;
	}
	list_add(&(opcConfig->topList), &g_opcConfigHead);
	return PARSER_OK;
}

/************************************************************
*Function    : opc_data
*Action      : opc protocol data processing
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
static enum FLT_RET opc_data(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	OPC_SESSION *session = NULL;

	if (NULL == hdr)
	{
		SCLogError("[%s:%d]invalid para, hdr(%p)", __func__, __LINE__, hdr);
		return FLTRET_CLOSE;
	}

	switch (ev)
	{
	case FLTEV_ONCLIIN:         /* To connect server */
	{
		session = opc_allocSession();
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
			return opc_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(int) != (unsigned int)len))
		{
			SCLogError("[%s:%d]invalid para, buff(%p), len(%u)", __func__, __LINE__, buff, (unsigned int)len);
			return opc_closeSession(hdr, (int)len, "Invalid socket len");
		}

		isok = *((int *)buff);
		if (0 == isok)
		{
			SCLogError("[%s:%d]connect server failed, sock(%d), ssid(%u)", __func__, __LINE__, isok, hdr->sessionid);
			return opc_closeSession(hdr, (int)len, "Invalid socket fd");
		}

		SCLogInfo("[%s:%d]connect server success, sock(%d), ssid(%u)", __func__, __LINE__, isok, hdr->sessionid);

		session = hdr->user;
		session->connecting = OPC_CONNECTED;
		if (0 < evbuffer_get_length(session->reqBuf))
		{
			return opc_data(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		}

		break;
	}

	case FLTEV_ONSOCKDATA:      /* Receive client or server data */
	{
		if (NULL == hdr->user)
		{
			SCLogError("[%s:%d]invalid para, hdr(%p), user(%p)", __func__, __LINE__, hdr, hdr->user);
			return opc_closeSession(hdr, (int)len, "User data is NULL");
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
					return opc_closeSession(hdr, (int)len, "Add data to request eventbuffer");
				}

				SCLogInfo("[%s:%d]svr not ready, delay.... ssid(%u)", __func__, __LINE__, hdr->sessionid);
			}
			return FLTRET_OK;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != opc_handleClientReq(hdr, session, buff, len))
			{
				return opc_closeSession(hdr, (int)len, "Handle client request data");
			}
		}
		else
		{
			if (PARSER_OK != opc_handleServerReq(hdr, session, buff, len))
			{
				return opc_closeSession(hdr, (int)len, "Handle server request data");
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
			return opc_closeSession(hdr, (int)len, "User data is NULL");
		}

		if ((NULL == buff) || ((unsigned int)sizeof(obj) != (unsigned int)len))
		{
			SCLogError("[%s:%d]invalid para, buff(%p), len(%u)", __func__, __LINE__, buff, (unsigned int)len);
			return opc_closeSession(hdr, (int)len, "Invalid data obj");
		}

		session = hdr->user;

		obj = (ForwardObject *)buff;

		SCLogInfo("[%s:%d]receive data from fwd, len(%u), sessionid(%u)",
			__func__, __LINE__, (unsigned int)obj->buffdata.len, hdr->sessionid);

		if (PARSER_OK != opc_checkFwdObjData(hdr, obj))
		{
			break;
		}

		if (NULL != hdr->svr)
		{
			if (PARSER_OK != opc_handleClientRsp(hdr, session, obj))
			{
				return opc_closeSession(hdr, (int)len, "Handle client response data");
			}
		}
		else
		{
			if (PARSER_OK != opc_handleServerRsp(hdr, session, obj))
			{
				return opc_closeSession(hdr, (int)len, "Handle server response data");
			}
		}

		break;
	}

	case FLTEV_ONSOCKERROR:     /* Close session */
	{
		return opc_closeSession(hdr, 0, NULL);
	}

	default:                    /* Not handle, return ok */
		break;

	}

	return FLTRET_OK;
}

/************************************************************
*Function    : opc_free
*Action      : opc free
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_free(void)
{
	if (g_opcDynamicPort)
	{
		SCFree(g_opcDynamicPort);
	}
	g_opcDynamicPort = NULL;
	g_opcDynamicPortNum = 0;
	return FLTRET_OK;
}

/************************************************************
*Function    : opc_init
*Action      : opc init
*Input       : null
*Output      : null
*Return      : PARSER_OK         success
			   PARSER_ERROR      false
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static int opc_init(void)
{
	unsigned int size;

	if ((1024 > g_gapcfg->port_opc_begin) || (g_gapcfg->port_opc_begin > g_gapcfg->port_opc_end))
	{
		SCLogError("[%s:%d]invalid begin port(%u) and end port(%u), please check", __func__, __LINE__,
			g_gapcfg->port_opc_begin, g_gapcfg->port_opc_end);
		return PARSER_ERROR;
	}

	g_opcDynamicPortNum = (unsigned short)(g_gapcfg->port_opc_end - g_gapcfg->port_opc_begin + 1);
	size = ((unsigned int)g_opcDynamicPortNum) * ((unsigned int)sizeof(OPC_DYNAMIC_PORT));
	g_opcDynamicPort = (OPC_DYNAMIC_PORT *)SCMalloc(size);
	if (NULL == g_opcDynamicPort)
	{
		g_opcDynamicPortNum = 0;
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)", __func__, __LINE__, size);
		return PARSER_ERROR;
	}
	memset(g_opcDynamicPort, 0, size);

	INIT_LIST_HEAD(&g_opcConfigHead);

	return FLTRET_OK;
}

/************************************************************
*Function    : opc_checkData
*Action      : opc check data
*Input       : buff data
			   len  data len
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.7.12
*Instruction : first data seg
************************************************************/
static enum SVR_ID opc_checkData(const void *buff, size_t len)
{
	if ((2 < len) && !memcmp(buff, "\x05\x00", 2))
	{
		return SVR_ID_OPC;
	}
	return _SVR_ID_NONE;
}

/************************************************************
*Function    : g_filter_opc
*Action      : opc protocol processing
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2016.12.28
*Instruction : null
************************************************************/
static struct packet_filter g_filter_opc =
{
	SVR_ID_OPC,
	"opc parser",
	opc_init,
	opc_data,
	opc_free,
	opc_checkData
};

void parser_opc_pktfilter_reg()
{
	pktfilter_reg(&g_filter_opc);
}

void parser_opc_pktfilter_unreg()
{
	pktfilter_unreg(&g_filter_opc);
}
