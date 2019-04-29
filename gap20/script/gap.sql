
/* �����û�������Ȩ��(���ط����û���Զ�̷����û�) */
GRANT ALL ON *.* TO admin@'localhost' IDENTIFIED BY 'admin123!@#' WITH GRANT OPTION;
GRANT ALL ON *.* TO admin@'192.168.0.3' IDENTIFIED BY 'admin123!@#' WITH GRANT OPTION;
GRANT ALL ON *.* TO admin@'192.168.0.2' IDENTIFIED BY 'admin123!@#' WITH GRANT OPTION;

/*�������ݿ�*/
Create Database If Not Exists gapdb Character Set UTF8;

/* �������ݿ� */
Use gapdb;

/*�������ݱ�-������*/
Create Table If Not Exists operationlogs(
	id BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*��������(inner, outer)*/
	ip varchar(24),       /*IP��ַ*/
	user varchar(32),    /*�û���*/
	op varchar(24),       /*��������(add, edit, delete, view, login, export, ...)*/
	accesstype varchar(24),/* �������� */
	content varchar(512),  /*��������*/
	result int,/* Error code */
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;


/*�������ݱ�-ϵͳ��־��*/
Create Table If Not Exists syslogs(
	id   BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*��������(inner, outer)*/
	module  varchar(64),  	/*ģ����*/
	level   INT,          	/*�ȼ�(0:critical, 1:error, 2:warn, 3:info)*/
	content varchar(512),   /*����*/
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;


/*�������ݱ�-�¼���Ʊ�*/
Create Table If Not Exists eventauditlogs(
	id	BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*��������(inner, outer)*/
	user varchar(32),    	/*�û�*/
	module	varchar(32), 	/*ģ��*/
	action	varchar(32), 	/*����*/
	content varchar(512),  	/*����*/
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;

/*�������ݱ�-������Ʊ�*/
Create Table If Not Exists accessauditlogs(
	id	BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),  /*��������(inner, outer)*/
	sessionID	BIGINT,
	sip  varchar(24),     /*ԴIP*/
	dip  varchar(24),     /*Ŀ��IP*/
	protocol	INT,
	sport INT,    /*Դ�˿�*/
	dport INT,     /*Ŀ�Ķ˿�*/
	application  varchar(32),   /*Ӧ��Э�飺FTP��HTTP....*/
	user  varchar(32),   /*�û���*/
	hostname	varchar(32),
	level   INT,          /*�ȼ�(0:critical, 1:error, 2:warn, 3:info)*/
	rule varchar(128),      /*����*/
	rulehitresult	varchar(32),
	packetlength	INT,
	content varchar(512), /*���� */
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)Engine InnoDB;

/*�������ݱ�-�Ựͳ�Ʊ�*/
Create Table If Not Exists sessionlogs(
  id	BIGINT PRIMARY KEY auto_increment,
	boardtype varchar(24),   /*��������(inner, outer)*/
	sessionid    INT,      /*�ỰID*/
	innerifname   varchar(8),/*�Ự�������ڶ˻�����ӿ� */
	outerifname   varchar(8),/*�Ự��������˻�����ӿ� */
	user	varchar(32), /*�Ự�������û� */
	route	varchar(256), /*�Ự������·�ɹ��� */
	state	varchar(8), /* �Ự��״̬�������ӻ��������ӡ���ر�*/
	outerip	varchar(24), /*�����豸IP */
	outerport	INT, /* �����豸�˿�*/
	innerip	varchar(24), /* �����豸IP*/
	innerport	INT, /*�����豸�˿� */
	protocol	INT,/*����Э�飺TCP,UDP*/
	application  varchar(32),   /*Ӧ��Э�飺FTP��HTTP....*/
	recvbytes	BIGINT, /*�����ֽ��� */
	sendbytes	BIGINT, /* �����ֽ���*/
	recvpackets	BIGINT, /* �������ݰ���*/
	sendpackets	BIGINT, /*�������ݰ��� */
	recvbps	BIGINT, /* �����ֽ�����*/
	sendbps	BIGINT, /*�����ֽ����� */
	recvpps	BIGINT, /*�������ݰ����� */
	sendpps	BIGINT, /*�������ݰ����� */
	createdtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP /*�Ự���ɵ�ʱ��*/
)Engine InnoDB;

/*�������ݱ�-Web����ϵͳ������ʵ�ַ��*/
Create Table If Not Exists webaccesslist(
	id   BIGINT PRIMARY KEY auto_increment,
	ip   varchar(24),       /*IP��ַ*/
	mac  varchar(24)       /*MAC��ַ*/
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
