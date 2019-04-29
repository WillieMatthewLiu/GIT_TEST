#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

#include "thread.h"
#include "app_common.h"
#include "bitops.h"
#include "command.h"
#include "util-lock.h"
#include "up_defs.h"
#include "ha.h"

int upgrade_check_rpm(const char * path)
{
    FILE *fp_read = NULL;
    char buf_t[UPGRADE_BUF_LEN] = {0};

    sprintf(buf_t, "rpm -qpi %s | grep Architecture | cut -d ' ' -f 2", path);
    fp_read = popen(buf_t, "r");
    if(fp_read == NULL) 
    {
        return -1;
    }

    if(fgets(buf_t, UPGRADE_BUF_LEN, fp_read) == NULL) 
    {
        pclose(fp_read);
        fp_read = NULL;
        return -1;
    }
    pclose(fp_read);
    fp_read = NULL;

    if((strncmp("ked", buf_t, 3) == 0) || (strncmp("mips64_nf", buf_t, 9) == 0)) 
    {
        return 0;
    }
    
    return -1;
}

int upgrade_pre_tftp(const char *dest_dir, const char *filename, char *ip_serv)
{
    int ret;
    char buf[UPGRADE_BUF_LEN];
    char cmd[UPGRADE_BUF_LEN] = {0};

    snprintf(cmd, UPGRADE_BUF_LEN,
        "cd %s && tftp -gr %s -b 8192 %s 2>&1 && ls %s", 
        dest_dir, filename, ip_serv, filename);

    SCLogInfo("cmd: %s\n", cmd);
    ret = cmd_system_getout(cmd, buf, UPGRADE_BUF_LEN);
    if(!ret || strncmp(buf, filename, strlen(filename)) != 0) {
        return -1;
    }

    return 0;
}

int upgrade_rpm(char *rpm_src, unsigned char type)
{
    int ret;
    ret = cmd_system_novty_arg("rpm -Uvh %s --nodeps --force 2>&1", 
                    rpm_src);
    if(ret)
        return -1;

    cmd_system_novty("sync");

    return 0;
}

int upgrade_file(char *file_src, char *file_dst, unsigned char type)
{
    int ret;

    ret = cmd_system_novty_arg("ls %s 2>&1 && /bin/cp -rf %s %s 2>&1", 
        file_src, file_src, file_dst);

    return ret;
}
int upgrade_check_cert(const char* cert)
{
    char buf[UPGRADE_BUF_LEN];
    char cmd[UPGRADE_BUF_LEN];
    /* verify crt with ca */
    snprintf(cmd, UPGRADE_BUF_LEN, "openssl verify -CAfile %s %s", CA_FULLNAME, cert);
    if(cmd_system_getout(cmd, buf, UPGRADE_BUF_LEN) <= 0 
        || NULL == strstr(buf, "OK"))
    {
        return -1;
    }
    return 0;
}

int upgrade_check_privatekey(const char* key)
{
    int ret;
    SSL_CTX *ctx;
    
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_method());
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    ret = SSL_CTX_load_verify_locations(ctx, CA_FULLNAME, NULL);
    if (ret != 1)
    {
        return -1;
    }
    ret = SSL_CTX_use_certificate_file(ctx, CERT_FULLNAME, SSL_FILETYPE_PEM);
    if (ret != 1)
    {
        return -1;
    }
    ret = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    if (ret != 1)
    {
        return -1;
    }
    ret = SSL_CTX_check_private_key(ctx);
    if (ret != 1)
    {
        return -1;
    }
    return 0;
}

int upgrade_encrypt_keyfile(char *file_src)
{
    /* maybe check keyfile with pub */
    if(cmd_system_novty_arg("load_rsa_key prikey %s 2>&1 ", 
             file_src))
        return -1;
 
    return 0;
}

#define GET_BOOTFILE_NAME "acorn_eeprom read bootfile"

char * upgrade_panter(int board_type, int backup, const char *sname){
    char *ret;
    vector v = vector_init(2);
    
    char *cmd1 = "configure terminal";
    char cmd2[256]={0};
    if(backup)
        snprintf(cmd2, 256, "update image %s tftp 192.168.0.2", sname);
    else
        snprintf(cmd2, 256, "reset-update image %s tftp 192.168.0.2", sname);
    vector_set(v, cmd1);
    vector_set(v, cmd2);
    ret = do_cmdv(board_type, v, 10);
    if(ret && ret[0]){
        return ret;
    }
    return NULL;
}

char * panter_pull_image(int board_type, int backup, const char *sname)
{
    char *ret;
    vector v = vector_init(2);
    
    char *cmd1 = "configure terminal";
    char cmd2[256]={0};
    if(backup)
    {
        snprintf(cmd2, 256, "update pull image %s tftp 192.168.0.2", sname);
    }
    else
    {
        snprintf(cmd2, 256, "reset-update pull image %s tftp 192.168.0.2", sname);
    }
    
    vector_set(v, cmd1);
    vector_set(v, cmd2);
    ret = do_cmdv(board_type, v, 0);
    if(ret && ret[0]){
        return ret;
    }
    return NULL;
}

char * panter_pull_image_reboot(int board_type, int backup, const char *sname)
{
    char *ret;
    vector v = vector_init(2);
    
    char *cmd1 = "configure terminal";
    char cmd2[256]={0};
    if(backup)
    {
        snprintf(cmd2, 256, "update reboot-pull image %s tftp 192.168.0.2", sname);
    }
    else
    {
        snprintf(cmd2, 256, "reset-update reboot-pull image %s tftp 192.168.0.2", sname);
    }
    
    vector_set(v, cmd1);
    vector_set(v, cmd2);
    ret = do_cmdv(board_type, v, 0);
    if(ret && ret[0]){
        return ret;
    }
    return NULL;
}

int upgrade_stb(char *update, const char *sname, int one_click)
{
    int sockfd;
    struct ifreq tmp;
    struct in_addr ip;
    char cmd[UPGRADE_BUF_LEN] = {0};
    int len;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if( sockfd < 0)
    {
        perror("create socket fail\n");
        return -1;
    }

    strncpy(tmp.ifr_name, HA_INTERFACE, sizeof(tmp.ifr_name)-1);

    if( (ioctl(sockfd, SIOCGIFADDR, &tmp)) < 0 )
    {
        printf("ioctl error %s\n", strerror(errno));
        return -1;
    }
    else
        ip =  ((struct sockaddr_in *)&(tmp.ifr_addr))->sin_addr;

    if(one_click)
        len = snprintf(cmd, sizeof(cmd), "vtysh -c 'configure terminal' -c '%s all image %s tftp %s'", 
                                    update, sname, inet_ntoa(ip));
    else
        len = snprintf(cmd, sizeof(cmd), "vtysh -c 'configure terminal' -c '%s stb image %s tftp %s'", 
                                    update, sname, inet_ntoa(ip));
    
    cmd[len] = 0;
    if (HA_SUCCESS != ha_data_sync(UPGRADE_MOD_ID, (const char*)cmd, len + 1)){
        SCLogInfo("Call ha_data_sync failed.");
        return -1;
    }
    SCLogInfo("send cmd: %s\n", cmd);
    return 0;
}

void upgrade_image(int backup, const char *path)
{
    char *ret;
    char buffer[256];
    if(backup){
        if(get_result_by_system(buffer, sizeof(buffer), GET_BOOTFILE_NAME) > 0)
            cmd_system_novty_arg("echo %s > /data/update_last_bootfile", buffer);
        /* touch flag to updata */
        cmd_system_novty_arg("touch /data/upgrade_need_backup");
    }else
    {
        /* touch flag to updata */
        cmd_system_novty_arg("touch /data/upgrade_reset");
    }

    /* set bootfile name */
    cmd_system_novty_arg("rm -f /boot/vmlinux.tmp; cp -f %s /boot/vmlinux.tmp", path);
    cmd_system_novty_arg("acorn_eeprom write bootfile vmlinux.tmp");

}

void upgrade_image_reboot(int backup, const char *path)
{
    upgrade_image(backup, path);
    
    /* reboot */
    cmd_system_novty("sleep 1");
    cmd_system_novty("sleep 1; reboot&");
}

int upgrade_pre_ftp(const char src, 
    const char *dest,
    const char *server,
    const char *username,
    const char *userpwd){
    cmd_system_novty_arg("wget ftp://%s:%s@%s/%s -T 20 -O %s &> /dev/null",
        username, userpwd, server,src, dest);
    if( access(dest, R_OK) < 0){
        return -1;
    }
    return 0;
}

