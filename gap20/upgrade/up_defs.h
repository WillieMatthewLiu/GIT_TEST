#ifndef _UP__DEFS_H_
#define _UP__DEFS_H_

#define BOARDTYPE_IN       0 
#define BOARDTYPE_OUT      1
#define BOARDTYPE_ARBITER  2


#define TO_ARTIBER_DEV 0
#define TO_OUTER_DEV   0
#define UPGRADE_PORT  8882

#define TMP_DIR "/tmp/"

#define CA_FULLNAME "/etc/openssl/private/ca.crt"
#define CERT_FULLNAME "/etc/openssl/certs/gap.crt"

#define UPGRADE_BUF_LEN		(512)
#define UPGRADE_TYPE_USB	(1)
#define UPGRADE_TYPE_TFTP	(2)
#define MEDIA_MOUNT		(1)
#define MEDIA_UMOUNT		(2)

#define HA_INTERFACE "eth7"
#define UPGRADE_VTY_PORT 2603
#define UPGRADE_MOD_ID 0x08000000|UPGRADE_VTY_PORT
#define ICMP_MAX_SEND 1000

/* support upgrade file type */
#define UP_FILE_TYPE_RPM   1
#define UP_FILE_TYPE_CA    2
#define UP_FILE_TYPE_CERT  3
#define UP_FILE_TYPE_KEY   4
#define UP_FILE_TYPE_IMAGE 5
#define UP_FILE_TYPE_IMAGE_RST 6


/* upgrade msg type */
#define UP_MSG_FILE_SUMMARY 1
#define UP_MSG_FILE_TRANS   2  
#define UP_MSG_DO_UPGRADE   3
#define UP_MSG_RUN_CMD     4

enum{
    UP_SUCCESS = 0,
    UP_ERROR_CONNECT_SERV,
    UP_ERROR_FILE_TRANS,
};

#define ENUM_UP_ERROR_TYPE_CASE(x)   case x: return(#x + 3);

static inline const char *up_error_str(int err){
    switch(err){
    ENUM_UP_ERROR_TYPE_CASE(UP_SUCCESS)
    ENUM_UP_ERROR_TYPE_CASE(UP_ERROR_CONNECT_SERV)
    ENUM_UP_ERROR_TYPE_CASE(UP_ERROR_FILE_TRANS)
    default:
        return "unknown";
    }
};

struct file_summary{
    int      type;
    char     path[256];
    uint64_t size;
    char     md5_sum[32];
};

#define MAX_TRANS_LEN (16000-64)
struct file_trans{
    int len;
    int frame; /* 0 - no frame or last, 1- have next */
    char data[MAX_TRANS_LEN]; 
};

struct uprade_packet{
    int msg_type;
    union{
        struct file_summary file_sum;
        struct file_trans trans;
        char data[MAX_TRANS_LEN];
    }u;
};

extern int boardtype;
extern int current_ha_state ;
int upgrade_init(int board, const char *path, const char *ip_str, uint16_t port );
char *do_upgrade(int board_type, int type, const char * path);
char * check_upgrade_arbiter();

int upgrade_check_rpm(const char * path);
int upgrade_pre_tftp(const char *dest_dir, const char *filename, char *ip_serv);
int upgrade_rpm(char *rpm_src, unsigned char type);
int upgrade_file(char *file_src, char *file_dst, unsigned char type);
int upgrade_encrypt_keyfile(char *file_src);
int upgrade_check_cert(const char* cert);
int upgrade_check_privatekey(const char* key);
void upgrade_image(int backup, const char *path);
void upgrade_image_reboot(int backup, const char *path);
char * panter_pull_image(int board_type, int backup, const char *sname);
char * panter_pull_image_reboot(int board_type, int backup, const char *sname);
char * do_cmd(int board_type, char *cmd);
char *do_cmdv(int board_type, vector v, int timeout);

#endif
