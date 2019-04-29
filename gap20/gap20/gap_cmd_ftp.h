#ifndef _GAP_CMD_FTP_H_
#define _GAP_CMD_FTP_H_

#define VIRUS_DETECTION_TOOL_PATH "/home/root/ruising/"
#define FTP_VIRUS_DETECTION_FILE_PRE "/run/ftp_tmp"

enum ftp_cmd {
	FTP_CMD_DELE = 0,
	FTP_CMD_NLST,
	FTP_CMD_LIST,
	FTP_CMD_CWD,
	FTP_CMD_XCWD,
	FTP_CMD_RETR,
	FTP_CMD_STOR,
	FTP_CMD_XPWD,
	FTP_CMD_XMKD,
	FTP_CMD_RNFR,
	FTP_CMD_RNTO,
	FTP_CMD_XRMD,
	FTP_CMD_APPE,
	FTP_CMD_OTHER
};

struct ftp_list_item {
	struct list_head n_list;
	char name[NAME_LEN + 1];
};

struct ftp_rule_group
{
	char groupname[NAME_LEN + 1];
	int rule_work; //0: all rule don' work, 1: all rule work
	struct json_object *json_rule;

	/* replace banner info */
	char *banner_info;

	/* user filter info */
	int user_rule_mode; // 0: black 1: white
	char *users_str;
	struct hash *users;

	/* cmd filter info */
	int cmd_rule_mode; // 0: black 1: white
	char *cmds_str;
	struct hash *cmds;

	/* up file filter info */
	int up_virus_detection; //0: disable 1:enable
	uint64_t max_up_file_len; // max allowable up file length
	int up_rule_mode; // 0: black 1: white
	char *up_types_str;
	struct hash *up_types;

	/* down file filter info */
	int down_virus_detection; //0: disable 1:enable
	uint64_t max_down_file_len; // max allowable down file length
	int down_rule_mode; // 0: black 1: white
	char *down_types_str;
	struct hash *down_types;

	//�ؼ��ֹ�����Ϣ
	int  nKeyCount;			//�ؼ��ָ��������50��
	int  nKeyLength[50];	//�ؼ��ָ�����������
	char chKeyWord[2048];	//�ؼ�������
};		

int ftp_check_user_privilege(struct ftp_rule_group *group, const char *user);
int ftp_check_cmd_privilege(struct ftp_rule_group *group, const char *cmd);
int ftp_check_upfile_type_privilege(struct ftp_rule_group *group, const char *file_type);
int ftp_check_downfile_type_privilege(struct ftp_rule_group *group, const char *file_type);
int ftp_check_upfile_virus_detection(struct ftp_rule_group *group);
int ftp_check_downfile_virus_detection(struct ftp_rule_group *group);
uint64_t ftp_get_max_upfile_length(struct ftp_rule_group *group);
uint64_t ftp_get_max_downfile_length(struct ftp_rule_group *group);
int ftp_get_banner_info(struct ftp_rule_group *group, char *buf, int len);
int ftp_file_virus_detection(char *filepath);
int ftp_config_write(struct vty *vty);
void ftp_del_rule_group_extern(void *protocol_rule);

/************************************************************************************************
1.��飺   ���ڴ��ַ��1�в����ڴ��ַ��2�ڵ�һ�γ��ֵ�λ��
2.������   str1 �ڴ��ַ��1
		   n1   �ڴ��ַ��1�ĳ���
		   str2 �ڴ��ַ��2
		   n2   �ڴ��ַ��2�ĳ���
3.����ֵ:  �����ڴ��ַ��2���ڴ��ַ��1�е�һ�γ��ֵĵ�ַ����NULLδ���ҵ�
************************************************************************************************/
char* memstr(const char* str1, int n1, const char* str2, int n2);

int ftp_check_keyword(struct ftp_rule_group* pGroup, const char* pData, int nDataLen);

void ftp_conf_cmd_init(void);
void ftp_show_cmd_init(unsigned int machine);
void ftp_cmd_init(void);
void ftp_cmd_exit(void);

#endif
