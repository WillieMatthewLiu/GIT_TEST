#pragma once


#define SVRID_IS_UDP_FAMILY(id) (id >= SVR_ID_UDP)
#define SVRID_IS_TCP_FAMILY(id) (id < SVR_ID_UDP)

enum SVR_ID
{
	_SVR_ID_NONE,
	SVR_ID_PCAP,

	// TCP family under here
	SVR_ID_TCP,
	SVR_ID_SSL,
	SVR_ID_HTTP,
	SVR_ID_HTTPS,
	SVR_ID_FTP,
	SVR_ID_FTPDATA,
	SVR_ID_TDCS,
	SVR_ID_OPC,
	SVR_ID_OPCSSDP,
	SVR_ID_OPCDATA,
	SVR_ID_IEC104,
	SVR_ID_SSH,
	SVR_ID_SMTP,
	SVR_ID_POP3,
	SVR_ID_NETBIOS,
	SVR_ID_ORCL,
	SVR_ID_MSSQL,
	SVR_ID_RTSP,
	SVR_ID_DB2,
	SVR_ID_MODBUS,
	SVR_ID_MYSQL,
	// UDP family under here
	SVR_ID_UDP,
	SVR_ID_SIP,
	SVR_ID_SIPDATA,
	SVR_ID_RTSPDATA,

	_SVR_ID_COUNT,
};

#define SVR_ID_TO_NAME_MAP					\
{											\
	{ _SVR_ID_NONE, "_SVR_ID_NONE" },		\
	{ SVR_ID_PCAP, "PCAP" },				\
											\
	/* TCP family under here */				\
	{ SVR_ID_TCP, "TCP" },					\
	{ SVR_ID_SSL, "SSL" },					\
	{ SVR_ID_HTTP, "HTTP" },				\
	{ SVR_ID_HTTPS, "HTTPS" },				\
	{ SVR_ID_FTP, "FTP" },					\
	{ SVR_ID_FTPDATA, "FTPDATA" },			\
	{ SVR_ID_TDCS, "TDCS" },				\
	{ SVR_ID_OPC, "OPC" },					\
	{ SVR_ID_OPCSSDP, "OPCSSDP" },		    \
	{ SVR_ID_OPCDATA, "OPCDATA" },		    \
	{ SVR_ID_IEC104, "IEC104" },			\
	{ SVR_ID_SSH, "SSH" },					\
	{ SVR_ID_SMTP, "SMTP" },				\
	{ SVR_ID_POP3, "POP3" },				\
	{ SVR_ID_NETBIOS, "NETBIOS" },			\
	{ SVR_ID_ORCL, "ORCL" },				\
	{ SVR_ID_MSSQL, "MSSQL" },				\
	{ SVR_ID_RTSP, "RTSP" },				\
	{ SVR_ID_DB2,"DB2"},					\
    { SVR_ID_MODBUS, "MODBUS"},             \
	{ SVR_ID_MYSQL, "MYSQL"},				\
											\
	/* UDP family under here */				\
	{ SVR_ID_UDP, "UDP" },					\
	{ SVR_ID_SIP, "SIP" },					\
	{ SVR_ID_SIPDATA, "SIPDATA" },          \
	{ SVR_ID_RTSPDATA, "RTSPDATA" },		\
	{ _SVR_ID_COUNT, "_SVR_ID_COUNT" }		\
}

