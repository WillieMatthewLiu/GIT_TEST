/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_opc.h
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.2.7
Description    : OPC protocol process
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#ifndef __PARSER_OPC_H__
#define __PARSER_OPC_H__

/* Byte width: for unicode */
#define OPC_CHAR_WIDE_SIZE          2

/* OPC characteristic information length */
#define OPC_DATA_SIGN_LEN           10

/* String format IP and port cache length */
#define OPC_IP2_BUFF_LEN            32
#define OPC_IP_BUFF_LEN             16
#define OPC_PORT_BUFF_LEN           6

/* UNICODE format IP and port cache length */
#define OPC_UNICODE_IP2_BUFF_LEN    64
#define OPC_UNICODE_IP_BUFF_LEN     32
#define OPC_UNICODE_PORT_BUFF_LEN   12

/* OPC application cache size */
#define OPC_BUFF_DATA_LEN           128

/* OPC data header length */
#define OPC_HEAD_LEN                16

/* OPC BIND header length */
#define OPC_HEAD_BIND_LEN           12

/* OPC Ctx Item length */
#define OPC_CTX_ITEM_LEN            44

/* OPC REQUEST & RESPONSE header length */
#define OPC_REQ_HEAD_LEN            8
#define OPC_RSP_HEAD_LEN            OPC_REQ_HEAD_LEN

/* OPC dcom length */
#define OPC_DCOM_LEN                28

/* OPC MAX OPNUM */
#define OPC_MAX_OPNUM               50

/* OPC data increase length */
#define OPC_DATA_INCREASE_LEN       128

/* OPC matching content keyword length */
#define OPC_DATA_KEY_LEN            5

/* OPC analysis results cache size */
#define OPC_ANALY_RESULT_LEN        16

/* OPC to analyze data length */
#define OPC_ANALY_CONTENT_LEN       32

/* offset */
#define OPC_MEM_OFFSET(struc, e)    ((unsigned short)((void *)(&(((struc *)0)->e)) - (void *)0))

/* 16 bit byte order swap */
#define BYTE_SEQ_SWITCH_16(x)       ((unsigned short)(((((unsigned short)x) & 0x00ffU) << 8) \
                                        | ((((unsigned short)x) & 0xff00U) >> 8)))

/* 32 bit byte order swap */
#define BYTE_SEQ_SWITCH_32(x)       ((unsigned int)(((((unsigned int)x) & 0x000000ffU) << 24) \
                                        | ((((unsigned int)x) & 0x0000ff00U) << 8) \
                                        | ((((unsigned int)x) & 0x00ff0000U) >> 8) \
                                        | ((((unsigned int)x) & 0xff000000U) >> 24)))

/* Session connection status */
typedef enum OPC_CONNECT_STATUS_E
{
	OPC_DISCONNECT = 0,
	OPC_CONNECTING,
	OPC_CONNECTED
} OPC_CONNECT_STATUS;

/* Data processing rule */
typedef enum OPC_DATA_RULE_E
{
	OPC_DATA_NORMAL = 0,
	OPC_DATA_DROP,
	OPC_DATA_CLOSE
} OPC_DATA_RULE;

/* Data Mode Index id */
typedef enum OPC_DATA_MODE_E
{
	OPC_DATA_RW = 0,
	OPC_DATA_R
} OPC_DATA_MODE;

/* OPC Interface Index id */
typedef enum OPC_INTERFACE_INDEX_E
{
	ISYSTEMACTIVATOR_ID = 0,
	IOXIDRESOLVER_ID,
	IREMUNKNOWN2_ID,
	IOPCCOMMON_ID,
	IOPCSERVERLIST_ID,
	IOPCSERVERLIST2_ID,
	IOPCSERVER_ID,
	ICONNECTIONPOINTCONTAINER_ID,
	ICONNECTIONPOINT_ID,
	IOPCBROWSESERVERADDRESSSPACE_ID,
	IENUMGUID_ID,
	IENUMSTRING_ID,
	IENUMOPCITEMATTRIBUTES_ID,
	IOPCGROUPSTATEMGT_ID,
	IOPCITEMMGT_ID,
	IOPCITEMPROPERTIES_ID,
	IOPCDATACALLBACK_ID,
	IOPCSYNCIO_ID,
	IOPCASYNCIO_ID,
	IOPCASYNCIO2_ID,
	IOPCITEMIO_ID,
	IOPCSYNCIO2_ID,
	IOPCASYNCIO3_ID,
	INTERFACE_BUTT_ID
} OPC_INTERFACE_INDEX;

/* OPC config information */
typedef struct OPC_CONFIG_INFO_S
{
	struct list_head topList;
	int valid;
	int mode;
	char *groupName;
	char *jstr;
} OPC_CONFIG_INFO;

/* OPC new routing information */
typedef struct OPC_NEW_ROUTE_S
{
	struct server *data_svr;
	struct OPC_NEW_ROUTE_S *next;
} OPC_NEW_ROUTE;

/* OPC session information */
typedef struct OPC_SESSION_S
{
	int connecting;
	unsigned int callId;
	unsigned short opnum;
	unsigned short interfaceId;
	int isReqbufSend;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
	OPC_NEW_ROUTE *routes;
} OPC_SESSION;

/* OPCSSDP session information */
typedef struct OPCSSDP_SESSION_S
{
	int connecting;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} OPCSSDP_SESSION;

/* OPCDATA session information */
typedef struct OPCDATA_SESSION_S
{
	int connecting;
	unsigned int callId;
	unsigned short opnum;
	unsigned short interfaceId;
	struct evbuffer *reqBuf;
	struct evbuffer *rspBuf;
} OPCDATA_SESSION;

/* OPCDATA Configure struct */
typedef struct OPCDATA_CONFIG_S
{
	char dataRule;
} OPCDATA_CONFIG;

/* OPC dynamic port occupancy information */
typedef struct OPC_DYNAMIC_PORT_S
{
	int isUsed;
	struct server *svr;
} OPC_DYNAMIC_PORT;

/* OPC data header information */
typedef struct OPC_HEAD_S
{
	unsigned char version;                  /**< 00:01 RPC version should be 5 */
	unsigned char version_minor;            /**< 01:01 minor version */
	unsigned char packetType;               /**< 02:01 packet type */
	unsigned char packetFlags;              /**< 03:01 flags (see PFC_... ) */
	unsigned char dataRepresentation[4];    /**< 04:04 NDR data representation format label */
	unsigned short fragLength;              /**< 08:02 total length of fragment */
	unsigned short authLength;              /**< 10:02 length of auth_value */
	unsigned int callId;                    /**< 12:04 call identifier */
} OPC_HEAD;

/* UUID structure */
typedef struct OPC_UUID_S
{
	unsigned int timeLow;
	unsigned short timeMid;
	unsigned short timeHiAndVersion;
	unsigned char clockSeq[2];
	unsigned char node[6];
} OPC_UUID;

/* OPC Ctx Item data header information */
typedef struct OPC_CTX_ITEM_S
{
	unsigned short contextId;
	unsigned short numTransItems;
	OPC_UUID uuid;
	unsigned short interfaceVer;
	unsigned short interfaceVerMinor;
	unsigned char transferSyntax[16];
	unsigned int ver;
} OPC_CTX_ITEM;

/* OPC Request data header information */
typedef struct OPC_REQUEST_S
{
	unsigned int allocHint;
	unsigned short contextId;
	unsigned short opnum;
} OPC_REQUEST;

/* OPC data header information */
typedef struct OPC_DCOM_S
{
	unsigned short versionMajor;
	unsigned short versionMinor;
	unsigned int flag;
	unsigned int reserved;
	OPC_UUID uuid;
} OPC_DCOM;

/* Opnum mapping */
typedef struct OPC_OPNUM_MAPPING_S
{
	int opnum;
	char *name;
} OPC_OPNUM_MAPPING;

/* Interface Table structure */
typedef struct OPC_INTERFACE_TABLE_S
{
	char *name;
	OPC_UUID uuid;
	OPC_OPNUM_MAPPING opnumMapping[OPC_MAX_OPNUM + 1];
} OPC_INTERFACE_TABLE;

/* OPC Response data header information */
typedef struct OPC_RESPONSE_S
{
	unsigned int allocHint;
	unsigned short contextId;
	unsigned char cancelCount;
	unsigned char reserve;
} OPC_RESPONSE;

/* ISystemActivator object data header */
typedef struct ISA_RCINSTANCE_THAT_S
{
	unsigned int flags;
	unsigned char extent[8];
	unsigned int cntData1;
	unsigned int cntData2;
	unsigned int signature;
	unsigned int objFlags;
	unsigned char iid[16];
	unsigned char clsid[16];
	unsigned int cbextension;
	unsigned int size;
	unsigned int totalsize;
	unsigned int reserved;
} ISA_RCINSTANCE_THAT;

/* CUSTOM structure */
typedef struct ISA_RCINSTANCE_THAT_CUS_S
{
	struct
	{
		unsigned char version;
		unsigned char endianness;
		unsigned short commonHeaderLength;
		unsigned int filler;
	} customHeader;

	struct
	{
		unsigned int objectBufferLength;
		unsigned int filler;
	} privateHeader;

	unsigned int totalSize;
	unsigned int customHeaderSize;
	unsigned int reserved;
	unsigned int destinationContext;
	unsigned int numActivationPropertyStructs;
	unsigned char classInfoClsid[16];

	struct
	{
		unsigned int referentID1;
		unsigned int referentID2;
		unsigned char reserved[4];
		unsigned int maxCount;
		unsigned char propertyStructGuid1[16];
		unsigned char propertyStructGuid2[16];
	} clsIdPtr;

	struct
	{
		unsigned int maxCount;
		unsigned int propertyDataSize1;
		unsigned int propertyDataSize2;
	} clsSizesPtr;
} ISA_RCINSTANCE_THAT_CUS;

/* OUTPUT structure */
typedef struct ISA_RCINSTANCE_THAT_PROP_OUTPUT_S
{
	struct
	{
		unsigned char Version;
		unsigned char Endianness;
		unsigned short CommonHeaderLength;
		unsigned int Filler;
	} CommonHeader;

	struct
	{
		unsigned int ObjectBufferLength;
		unsigned int Filler;
	} PrivateHeader;

	unsigned int NumInterfaces;

	struct
	{
		unsigned int ReferentID1;
		unsigned int ReferentID2;
		unsigned int ReferentID3;
		unsigned int MaxCount;
		unsigned char IID[16];
	} InterfaceIdsPtr;

	struct
	{
		unsigned int MaxCount;
		unsigned int ReturnValue;
	} ReturnValuesPtr;

	struct
	{
		unsigned int MaxCount;
		struct
		{
			unsigned int ReferentID;
			struct
			{
				unsigned int CntData1;
				unsigned int CntData2;
				struct
				{
					unsigned int Signature;
					unsigned int Flags;
					unsigned char IID[16];
					struct
					{
						unsigned int Flags;
						unsigned int PublicRefs;
						unsigned char OXID[8];
						unsigned char OID[8];
						unsigned char IPID[16];
					} STDOBJREF;

					struct
					{
						unsigned short NumEntries;
						unsigned short SecurityOffset;
						struct
						{
							unsigned short TowerId;
							unsigned char NetworkAddr[14];
						} StringBinding1;

						struct
						{
							unsigned short TowerId;
							unsigned char NetworkAddr[30];
						} StringBinding2;

						struct
						{
							unsigned short TowerId;
							unsigned char NetworkAddr[48];
						} StringBinding3;

						unsigned char Reserved[2];

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[2];
						} SecurityBinding1;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[2];
						} SecurityBinding2;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[2];
						} SecurityBinding3;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[2];
						} SecurityBinding4;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[2];
						} SecurityBinding5;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[2];
						} SecurityBinding6;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[2];
						} SecurityBinding7;
					} ResolerAddress;
				} OBJREF;
			} Interface;
		} InterfacePtr;
	} InterfacePtrsPtr;
} ISA_RCINSTANCE_THAT_PROP_OUTPUT;

/* REPLAY structure */
typedef struct ISA_RCINSTANCE_THAT_PROP_REPLY_S
{
	struct
	{
		unsigned char Version;
		unsigned char Endianness;
		unsigned short CommonHeaderLength;
		unsigned int Filler;
	} CommonHeader;

	struct
	{
		unsigned int ObjectBufferLength;
		unsigned int Filler;
	} PrivateHeader;

	unsigned char NULLPointer[4];

	struct
	{
		unsigned int ReferentID;
		struct
		{
			unsigned char OXID[8];
			struct
			{
				unsigned int ReferentID;
				unsigned char IRemUnknownInterfacePointerId[16];
				unsigned int AuthenticationHint;
				unsigned short VersionMajor;
				unsigned short VersionMinor;
				struct
				{
					unsigned int oxid;
					struct
					{
						unsigned short NumEntries;
						unsigned short SecurityOffset;
						struct
						{
							unsigned short TowerId;
							unsigned char NetworkAddr[28];
						} StringBinding1;

						struct
						{
							unsigned short TowerId;
							unsigned char NetworkAddr[38];
						} StringBinding2;

						struct
						{
							unsigned short TowerId;
							unsigned char NetworkAddr[62];
						} StringBinding3;

						unsigned char Reserved[2];

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[40];
						} SecurityBinding1;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[40];
						} SecurityBinding2;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[24];
						} SecurityBinding3;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[24];
						} SecurityBinding4;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[40];
						} SecurityBinding5;

						struct
						{
							unsigned short AuthnSvc1;
							unsigned short AuthnSvc2;
							unsigned char PrincName[40];
						} SecurityBinding6;
					} Bindings;
				} OxidBindings;
			} OxidBindingsPtr;
		} RemoteReply;
	} RemoteRequestPtr;
} ISA_RCINSTANCE_THAT_PROP_REPLY;

void opc_convHead(OPC_HEAD *opcHead);
void opc_convUuid(unsigned char flag, OPC_UUID *uuid);
void opc_convRequestHead(unsigned char flag, OPC_REQUEST *requestHead);

OPC_DATA_MODE opc_getDataMode(char *groupName);
void opc_delConfig(const char *groupName);
int opc_addConfig(OPC_CONFIG_INFO *opcConfig);

/* Opc config list head */
extern struct list_head g_opcConfigHead;

#endif

