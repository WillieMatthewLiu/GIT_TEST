
/* 创建用户并赋与权限(本地访问用户，远程访问用户) */
GRANT ALL ON *.* TO admin@'localhost' IDENTIFIED BY 'admin123!@#' WITH GRANT OPTION;
GRANT ALL ON *.* TO admin@'192.168.0.3' IDENTIFIED BY 'admin123!@#' WITH GRANT OPTION;
GRANT ALL ON *.* TO admin@'192.168.0.2' IDENTIFIED BY 'admin123!@#' WITH GRANT OPTION;

/*创建数据库*/
Create Database If Not Exists gapdb Character Set UTF8;

/* 进入数据库 */
Use gapdb;

/*创建数据表-操作表*/
Create Table If Not Exists operationlogs(
	id BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*机器类型(inner, outer)*/
	ip varchar(24),       /*IP地址*/
	user varchar(32),    /*用户名*/
	op varchar(24),       /*操作类型(add, edit, delete, view, login, export, ...)*/
	accesstype varchar(24),/* 访问类型 */
	content varchar(512),  /*操作内容*/
	result int,/* Error code */
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;


/*创建数据表-系统日志表*/
Create Table If Not Exists syslogs(
	id   BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*机器类型(inner, outer)*/
	module  varchar(64),  	/*模块名*/
	level   INT,          	/*等级(0:critical, 1:error, 2:warn, 3:info)*/
	content varchar(512),   /*内容*/
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;


/*创建数据表-事件审计表*/
Create Table If Not Exists eventauditlogs(
	id	BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*机器类型(inner, outer)*/
	user varchar(32),    	/*用户*/
	module	varchar(32), 	/*模块*/
	action	varchar(32), 	/*动作*/
	content varchar(512),  	/*内容*/
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;

/*创建数据表-访问审计表*/
Create Table If Not Exists accessauditlogs(
	id	BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*机器类型(inner, outer)*/
	sessionID	BIGINT,
	sip  varchar(24),     /*源IP*/
	dip  varchar(24),     /*目的IP*/
	protocol	INT,
	sport INT,    /*源端口*/
	dport INT,     /*目的端口*/
	application  varchar(32),   /*应用协议：FTP、HTTP....*/
	user  varchar(32),   /*用户名*/
	hostname	varchar(32),
	level   INT,          /*等级(0:critical, 1:error, 2:warn, 3:info)*/
	rule varchar(128),      /*规则*/
	rulehitresult	varchar(32),
	packetlength	INT,
	content varchar(512), /*内容 */
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;

/*创建数据表-会话统计表*/
Create Table If Not Exists sessionlogs(
  id	BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),   /*机器类型(inner, outer)*/
	sessionid    INT,      /*会话ID*/
	innerifname   varchar(8),/*会话所属的内端机网络接口 */
	outerifname   varchar(8),/*会话所属的外端机网络接口 */
	user	varchar(32), /*会话所属的用户 */
	route	varchar(256), /*会话所属的路由规则 */
	state	varchar(8), /* 会话的状态：已连接或正在连接、或关闭*/
	outerip	varchar(24), /*外网设备IP */
	outerport	INT, /* 外网设备端口*/
	innerip	varchar(24), /* 内网设备IP*/
	innerport	INT, /*内网设备端口 */
	protocol	INT,/*传输协议：TCP,UDP*/
	application  varchar(32),   /*应用协议：FTP、HTTP....*/
	recvbytes	BIGINT, /*接收字节数 */
	sendbytes	BIGINT, /* 发送字节数*/
	recvpackets	BIGINT, /* 接收数据包数*/
	sendpackets	BIGINT, /*发送数据包数 */
	recvbps	BIGINT, /* 接收字节速率*/
	sendbps	BIGINT, /*发送字节速率 */
	recvpps	BIGINT, /*接收数据包速率 */
	sendpps	BIGINT, /*发送数据包速率 */
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP /*会话生成的时间*/
)Engine InnoDB;

/*创建数据表-Web管理系统允许访问地址表*/
Create Table If Not Exists webaccesslist(
	id   BIGINT PRIMARY KEY auto_increment,
	ip   varchar(24),       /*IP地址*/
	mac  varchar(24)       /*MAC地址*/
)Engine InnoDB;

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for SystemEvents
-- ----------------------------
DROP TABLE IF EXISTS `SystemEvents`;
CREATE TABLE `SystemEvents` (
  `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `CustomerID` bigint(20) DEFAULT NULL,
  `ReceivedAt` datetime DEFAULT NULL,
  `DeviceReportedTime` datetime DEFAULT NULL,
  `Facility` smallint(6) DEFAULT NULL,
  `Priority` smallint(6) DEFAULT NULL,
  `FromHost` varchar(60) DEFAULT NULL,
  `Message` text,
  `NTSeverity` int(11) DEFAULT NULL,
  `Importance` int(11) DEFAULT NULL,
  `EventSource` varchar(60) DEFAULT NULL,
  `EventUser` varchar(60) DEFAULT NULL,
  `EventCategory` int(11) DEFAULT NULL,
  `EventID` int(11) DEFAULT NULL,
  `EventBinaryData` text,
  `MaxAvailable` int(11) DEFAULT NULL,
  `CurrUsage` int(11) DEFAULT NULL,
  `MinUsage` int(11) DEFAULT NULL,
  `MaxUsage` int(11) DEFAULT NULL,
  `InfoUnitID` int(11) DEFAULT NULL,
  `SysLogTag` varchar(60) DEFAULT NULL,
  `EventLogType` varchar(60) DEFAULT NULL,
  `GenericFileName` varchar(60) DEFAULT NULL,
  `SystemID` int(11) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- ----------------------------
-- Table structure for SystemEventsProperties
-- ----------------------------
DROP TABLE IF EXISTS `SystemEventsProperties`;
CREATE TABLE `SystemEventsProperties` (
  `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `SystemEventID` int(11) DEFAULT NULL,
  `ParamName` varchar(255) DEFAULT NULL,
  `ParamValue` text,
  PRIMARY KEY (`ID`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
