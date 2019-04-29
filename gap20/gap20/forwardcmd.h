#pragma once


enum FORWARD_COMMAND
{
	_FWDCMD_INTERNAL_BEGIN,
	_FWDCMD_CLI_IN,				// 通知另一端，客户端连进来了，ForwardObject::strdata有效，格式为“smac=xxx;sip=xxx;sport=xxx;dip=xxx;dport=xxx;uid=xxx;uname=xxx;dir=0/1;sif=xxx;dif=xxx”
	_FWDCMD_CONN_SVR,			// 通知另一端，连接指定的服务器，ForwardObject::strdata有效，表示要连接的服务器地址，格式为：1.2.3.4:80
	_FWDCMD_CONN_SVR_REPLY,		// 通知另一端，连接服务器成功/失败，ForwardObject::intdata有效，成功为1，失败为0
	_FWDCMD_SOCK_WINDOW,		// 通知另一端，调整后的window大小
	_FWDCMD_SOCK_CLOSED,		// 通知另一端，服务端网络断开，无扩展数据
	_FWDCMD_INTERNAL_END,

	FWDCMD_FORWARDDATA,			// 转发数据，ForwardObject::buffdata有效, ForwardObject::strdata有效，为具体待判断的行为信息
};

