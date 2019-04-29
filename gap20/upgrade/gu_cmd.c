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

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "app_common.h"
#include "bitops.h"
#include "thread.h"
#include "command.h"
#include "sockunion.h"
#include "util-lock.h"
#include "up_defs.h"


DEFUN(upgrade_inner,
    upgrade_inner_cmd,
    "upgrade (cacrt|crt|key|rpm) WORD tftp A.B.C.D",
    "Upgrade system component through Udisk or Tftp\n"
    "upgrade for inner side\n"
    "private certificate file type\n"
    "certificate file type\n"
    "private key file type\n"
    "rpm package file type\n"
    "source file name\n"
    "Upgrade from tftp server\n"
    "tftp server ipaddr\n")
{
    int ret = CMD_SUCCESS;
    char *file_type = argv[0];
    char *sname = argv[1];

    char filename[256];


    //cmd_system("echo close > /var/run/dog_fifo");
    snprintf(filename, 256, "%s%s", TMP_DIR, sname);

    if(argc == 3){
        if((ret = upgrade_pre_tftp(TMP_DIR, sname, argv[2])) != CMD_SUCCESS) {
            vty_out(vty, "load file %s fail.%s", sname, VTY_NEWLINE);
            return CMD_SUCCESS;
        }
    }
    
    if(strcmp("rpm", file_type) == 0) {
        if(upgrade_check_rpm(filename)){
            vty_out(vty, "%s has wrong file type, need rpm.%s", sname, VTY_NEWLINE);
            return CMD_SUCCESS;
        }
        upgrade_rpm(filename, UPGRADE_TYPE_TFTP);
    } else if(strcmp("key", file_type) == 0) {
        if(upgrade_check_privatekey(filename) < 0){
            vty_out(vty, "key verify fail. please upgrade cert first.%s", VTY_NEWLINE);
            return CMD_SUCCESS;
        }
    
        if(upgrade_encrypt_keyfile( filename) < 0)
            vty_out(vty, "load key fail.%s", VTY_NEWLINE);
    } else if(strcmp("cacrt", file_type) == 0) {
        upgrade_file(filename, CA_FULLNAME, UPGRADE_TYPE_TFTP);
        sync();
    } else if(strcmp("crt", file_type) == 0) {
        /* verify crt with ca */
        if(upgrade_check_cert(filename) < 0 )
        {
            vty_out(vty, "cert verify fail. please upgrade ca first.%s", VTY_NEWLINE);
            /* Delete tmp file */
            unlink(filename);
        }else{
            upgrade_file(filename, CERT_FULLNAME, UPGRADE_TYPE_TFTP);
            sync();
        }
    }

    vty_out(vty, "upgrade success, please reboot system to use new.%s", VTY_NEWLINE);

    //cmd_system("echo open > /var/run/dog_fifo");

    return CMD_SUCCESS;
}

ALIAS(upgrade_inner,
    upgrade_inner1_cmd,
    "upgrade inner (cacrt|crt|key|rpm) WORD tftp A.B.C.D",
    "Upgrade system component through Udisk or Tftp\n"
    "upgrade for inner side\n"
    "private certificate file type\n"
    "certificate file type\n"
    "private key file type\n"
    "rpm package file type\n"
    "source file name\n"
    "Upgrade from tftp server\n"
    "tftp server ipaddr\n");

ALIAS(upgrade_inner,
    upgrade_inner2_cmd,
    "upgrade inner (cacrt|crt|key|rpm) WORD",
    "Upgrade system component through Udisk or Tftp\n"
    "upgrade for inner side\n"
    "private certificate file type\n"
    "certificate file type\n"
    "private key file type\n"
    "rpm package file type\n"
    "source file name(default dir is /tmp/)\n");

DEFUN(upgrade_outer,
    upgrade_outer_cmd,
    "upgrade outer (cacrt|crt|key|rpm) WORD tftp A.B.C.D",
    "Upgrade system component through Udisk or Tftp\n"
    "upgrade for outer side\n"
    "private certificate file type\n"
    "certificate file type\n"
    "private key file type\n"
    "rpm package file type\n"
    "source file name\n"
    "Upgrade from tftp server\n"
    "tftp server ipaddr\n")
{
    char *ret ;
    char *file_type = argv[0];
    char *serverip  = argv[2];
    int type = 0;
    
    
    char filename[256];

    if(boardtype != BOARDTYPE_IN){
        vty_out(vty, "execute this command at Inner side.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    snprintf(filename, 256, "%s%s", TMP_DIR, argv[1]);
    if(argc == 3){
        if(upgrade_pre_tftp(TMP_DIR, argv[1], serverip)) {
            vty_out(vty, "load file %s fail.%s", argv[1], VTY_NEWLINE);
            return CMD_SUCCESS;
        }
    }
    
    if(strcmp("cacrt", file_type) == 0){
        type = UP_FILE_TYPE_CA;
    }
    else if(strcmp(file_type, "crt") == 0){
        type = UP_FILE_TYPE_CERT;
    }
    else if(strcmp(file_type, "key") == 0){
        type = UP_FILE_TYPE_KEY;
    }
    else if(strcmp(file_type, "rpm") == 0){
        type = UP_FILE_TYPE_RPM;
        if(upgrade_check_rpm(filename)){
            vty_out(vty, "%s has wrong file type, need rpm.%s", argv[1], VTY_NEWLINE);
            return CMD_SUCCESS;
        }
    }
    /* copy file to outer board and upgrade it */
    ret = do_upgrade(BOARDTYPE_OUT, type, argv[1]);
    if(ret)
        vty_out(vty, "%s%s", ret, VTY_NEWLINE);
    return CMD_SUCCESS;

}

ALIAS(upgrade_outer,
    upgrade_outer1_cmd,
    "upgrade outer (cacrt|crt|key|rpm) WORD",
    "Upgrade system component through Udisk or Tftp\n"
    "upgrade for outer side\n"
    "private certificate file type\n"
    "certificate file type\n"
    "private key file type\n"
    "rpm package file type\n"
    "source file name(default dir is /tmp/)\n");

DEFUN(upgrade_arbiter,
    upgrade_arbiter_cmd,
    "upgrade arbiter rpm WORD tftp A.B.C.D",
    "Upgrade system component through Udisk or Tftp\n"
    "Upgrade for aritber\n"
    "rpm package file type\n"
    "source file name\n"
    "tftp server ipaddr\n")
{
    int ret = CMD_SUCCESS;
    char *ret_str ;
    char filename[256];

    snprintf(filename, 256, "%s%s", TMP_DIR, argv[0]);
    
    if(boardtype != BOARDTYPE_IN){
        vty_out(vty, "execute this command at Inner side.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    
    //cmd_system("echo close > /var/run/dog_fifo");
    if(argc == 2){
        if((ret = upgrade_pre_tftp(TMP_DIR, argv[0], argv[1])) != CMD_SUCCESS) {
            vty_out(vty, "load file %s fail.%s", argv[1], VTY_NEWLINE);
            return CMD_SUCCESS;
        }
    }

    if(upgrade_check_rpm(filename)){
        vty_out(vty, "%s has wrong file type, need rpm.%s",  argv[0], VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    
    ret_str = do_upgrade(BOARDTYPE_ARBITER, UP_FILE_TYPE_RPM, argv[0]);

    //cmd_system("echo open > /var/run/dog_fifo");
    if(ret_str)
        vty_out(vty, "%s%s", ret_str, VTY_NEWLINE);

    return CMD_SUCCESS;
}

ALIAS(upgrade_arbiter,
    upgrade_arbiter1_cmd,
    "upgrade arbiter rpm WORD",
    "Upgrade system\n"
    "Upgrade for aritber\n"
    "rpm package file type\n"
    "source file name(default dir is /tmp/)\n");

DEFUN(_show_kernel_version,
    show_kernel_version_cmd,
    "show kernel version",
    SHOW_STR
    "linux kernel\n"
    "version\n")
{
    FILE *f;
    char buf[512]={};
    if((f = popen("cat /proc/version", "r")) == NULL){
        vty_out(vty, "show kernel version fail.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    fgets(buf, 512, f);
    pclose(f);

    vty_out( vty, "%s%s", buf, VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN(_show_kernel_version1,
    show_kernel_version1_cmd,
    "show (arbiter|outer) kernel version",
    SHOW_STR
    "show arbiter\n"
    "show outer\n"
    "linux kernel\n"
    "version string\n")
{
    char *str;
    if(strcmp(argv[0], "arbiter") == 0){
        str = do_cmd(BOARDTYPE_ARBITER, "show kernel version");
    }else{
        str = do_cmd(BOARDTYPE_OUT, "show kernel version");
    }

    vty_out(vty, "%s%s", str, VTY_NEWLINE);

    return CMD_SUCCESS;
}

#define GET_BOOT_FREESIZE  "df -m | grep /boot | awk '{print $4}'"
#define GET_DATALOG_FREESIZE  "df -m | grep data | awk '{print $4}'"
#define GET_SDA_PART_NUM "fdisk -l | grep \"^/dev/sda\" | wc -l"
#define CHECK_IMAGE "ShowImage %s | grep  \"Image is correct\" | wc -l"
#define CHECK_MOUNT "mount | grep \"/tmp/usb_mount\" | wc -l"
#define TMP_BOOT_FILE "/boot/tmp_update_file"
int check_bootfile(char* bootfile)
{
	return 1;
    char buffer[256];
    chdir("/boot");
    get_result_by_system(buffer, sizeof(buffer), CHECK_IMAGE, bootfile);
    if(atoi(buffer) == 1) {
        return 1;
    } else {
        return 0;
    }
}

DEFUN (_update_by_usb, 
        _update_by_usb_cmd,
        "(update|reset-update) usb {image WORD}",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate update by USB disk\n"
        "Indicate the update system image\n"
        "Specify update system image name\n"
      )
{
    char buffer[256];
    int result;
    int fd = 0;
    char *image_name = argv[1];
    char sda_part_no[16];
    char* mount_dev = NULL;
    int save_update = 0;
    char filename[256];

    snprintf(filename, 256, "%s%s", TMP_DIR, argv[1]);
    
    /* check whether is a save config update */
    if(strncmp(argv[0], "update", 6) == 0) {
        save_update = 1;
    }
    
    /* delete tmp download file if is exist */
    unlink(TMP_BOOT_FILE);

    /* check /boot partition least size is enough */
    get_result_by_system(buffer, sizeof(buffer), GET_BOOT_FREESIZE);
    result = atoi(buffer);
    if(result < 300) {
        vty_out(vty, "Boot partition available free size is not enough.");
        goto error_ret;
    }

    /* check /data/log partition least size is enough */
    if(save_update) {
        get_result_by_system(buffer, sizeof(buffer), GET_DATALOG_FREESIZE);
        result = atoi(buffer);
        if(result < 10) {
            vty_out(vty,"datalog partition available free size is not enough.");
            goto error_ret;
        }
    }
    
    /* check whether partition is need to be mount, if usb has many partitions, only mount sda */
    get_result_by_system(sda_part_no, sizeof(sda_part_no), GET_SDA_PART_NUM);
    if(atoi(sda_part_no) == 1) {
        mount_dev = "/dev/sda1";
    } else {
        mount_dev = "/dev/sda";
    }
    
    /* mount usb disk */
    cmd_system_arg("mkdir -p /tmp/usb_mount");
    cmd_system_arg("mount %s /tmp/usb_mount &> /dev/null", mount_dev);
    
    /* check mount ok */
    get_result_by_system(buffer, sizeof(buffer), CHECK_MOUNT);
    result = atoi(buffer);
    if(result <= 0 ) {
        vty_out(vty, "Mounting USB disk error, please check your USB disk.");
        goto error_ret;
    }
    
    vty_out(vty, "Copying image file, please wait a few minutes...\r\n");
    buffer_flush_all(vty->obuf, vty->fd);
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    cmd_system_arg("cp /tmp/usb_mount/%s %s &> /dev/null", image_name, TMP_BOOT_FILE);
    cmd_system_arg("umount /tmp/usb_mount &> /dev/null");

    /* check download OK */
    fd = open(TMP_BOOT_FILE, O_RDONLY);
    if(result < 0 || fd < 0) {
        vty_out(vty, "USB copy image file failed. Please check you USB disk.");
        goto error_ret;
    }
    if(fd > 0) {
        vty_out(vty,"USB copy image file done.");
        close(fd);
    }
    
    /* check image format */
    vty_out(vty, "Checking image file format, please waiting.\r\n" );
    buffer_flush_all(vty->obuf, vty->fd);
    if(check_bootfile(TMP_BOOT_FILE) == 0) {
        vty_out(vty, "Image File format error, please re-update.\r\n" );
        goto error_ret;
    }
    
    vty_out(vty, "\r\nThe system need to reboot to finish the update process. PLEASE DO NOT POWER OFF.\r\n" );
    /* load file OK, now start upgrade */
    upgrade_image_reboot( save_update, filename);
    
    return CMD_SUCCESS;

error_ret:
    return CMD_WARNING;
}

static int ping_outer(struct vty *vty, const char *out_ip_str)
{
    int i;
    FILE *fp_read = NULL;
    char buf[UPGRADE_BUF_LEN] = {0};
    char cmd[UPGRADE_BUF_LEN] = {0};
    char tag[64] = {0};

    SCLogInfo("enter .....................\n");
    snprintf(tag, UPGRADE_BUF_LEN, "bytes from %s", out_ip_str);
    snprintf(cmd, UPGRADE_BUF_LEN, "ping %s -c 1 -W 1", out_ip_str);

    for(i = 0; i < ICMP_MAX_SEND; i++)
    {
        fp_read = popen(cmd, "r");
        if(fp_read == NULL)
            return -1;
        while(fgets(buf + strlen(buf), UPGRADE_BUF_LEN, fp_read) != NULL);
        pclose(fp_read);
        fp_read = NULL;

        if(!strstr(buf, tag))
            break;

        SCLogInfo("sleep: %d\n", i+1);
        sleep(1);
        memset(buf, 0, UPGRADE_BUF_LEN);
    }

    SCLogInfo("exit i = %d .....................\n", i);
    return i;
}

DEFUN (_update_image, 
        update_image_cmd,
        "(update|reset-update) image FILENAME tftp A.B.C.D",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n"
        "Indicate use tftp\n"
        "tftp server ip address\n"
      )
{
    int result;
    int save_update = 0;
    char filename[256];
    char *ret;
    int reboot = 0;
    int one_click_upgrade = 0;


    snprintf(filename, 256, "%s%s", TMP_DIR, argv[1]);
    
    /* check whether is a save config update */
    if(strncmp(argv[0], "update", 6) == 0) {
        save_update = 1;
    }
    
    /* download image */
    //vty_out(vty, "Downloading image file, please wait a few minutes...\r\n");
    buffer_flush_all(vty->obuf, vty->fd);
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    if(argc ==3){
        /* is used tftp */
        result = upgrade_pre_tftp(TMP_DIR, argv[1], argv[2]);
        if(result < 0){
            vty_out(vty, "tftp get image file failed. Please check you host ip.%s", VTY_NEWLINE);
            goto error_ret;
        }
    }else if (argc ==5){
        result = upgrade_pre_ftp(argv[1], 
            filename, argv[2], argv[3], argv[4]);
        if(result < 0){
            vty_out(vty, "ftp get image file failed. Please check you host ip, user name and password.\%s", VTY_NEWLINE);
            goto error_ret;
        }
    }

    /* check download OK */
    if( access(filename, R_OK) < 0)
    {
        vty_out(vty, "get image file failed. Please check.%s", VTY_NEWLINE);
        goto error_ret;
    }
    
    /* check image format */
    //vty_out(vty, "Checking image file format, please waiting.\r\n" );
    buffer_flush_all(vty->obuf, vty->fd);

    if(check_bootfile(filename) == 0) {
        vty_out(vty, "Image File format error, please re-update.%s", VTY_NEWLINE);
        unlink(TMP_BOOT_FILE);
        goto error_ret;
    }

    SCLogInfo("\r\nThe system need to reboot to finish the update process. PLEASE DO NOT POWER OFF.\r\n" );
    /* load file OK, now start upgrade */
    if(strstr(vty->buf, "outer")){

        ret = upgrade_panter(BOARDTYPE_OUT, save_update, argv[1]);
        
    }else if (strstr(vty->buf, "arbiter")){

        ret = upgrade_panter(BOARDTYPE_ARBITER, save_update, argv[1]);
        
    }else if (strstr(vty->buf, "pull")) {

        vty_out(vty, "Downloading image file success, start upgrade ...%s", VTY_NEWLINE);
        if(strstr(vty->buf, "reboot-pull"))
            upgrade_image_reboot( save_update, filename); 
        else
            upgrade_image( save_update, filename); 
        
    }else if (strstr(vty->buf, "all")) {
    
        SCLogInfo("upgrade inner ...\n");
        /* upgrade inner */
        upgrade_image( save_update, filename); 

        SCLogInfo("upgrade outer ...\n");
        /* tell outer to pull image */
        ret = panter_pull_image(BOARDTYPE_OUT, save_update, argv[1]);
        SCLogInfo("ret: %s\n", ret);

        SCLogInfo("upgrade arbiter ...\n");
        /* tell arbiter to pull image and reboot system */
        ret = panter_pull_image_reboot(BOARDTYPE_ARBITER, save_update, argv[1]);
        SCLogInfo("ret: %s\n", ret);

        vty_out(vty, "%s%s", ret, VTY_NEWLINE);

    }else if (strstr(vty->buf, "stb") && (argc == 2)) { // upgrade stb, now run in active host

        if(strstr(vty->buf, "one-click"))
            one_click_upgrade = 1;
        
        result = upgrade_stb(argv[0], argv[1], one_click_upgrade);
        if(result < 0) {
            vty_out(vty, "send update cmd to stb failed. Please check link.%s", VTY_NEWLINE);
            goto error_ret;
        }
        vty_out(vty, "send update cmd to stb success.%s", VTY_NEWLINE);
        
    }else if (strstr(vty->buf, "stb") && (argc == 3)) { // upgrade stb, now run in standby host

        SCLogInfo("upgrade inner ...\n");
        /* upgrade inner */
        upgrade_image( save_update, filename); 
        
        SCLogInfo("upgrade outer ...\n");
        /* upgrade outer */
        ret = upgrade_panter(BOARDTYPE_OUT, save_update, argv[1]);  
        if(!ret)
            goto error_ret;
        SCLogInfo("ret: %s\n", ret);
        
        /* ping outer until ping failed */
        result = ping_outer(vty, "192.168.0.3"); 
        if(result < 0)
            goto error_ret;

        SCLogInfo("ping over ...\n");

        /* record arbiter need to upgrade */
        cmd_system_novty_arg("touch /data/stb_arbiter_need_upgrade");
        cmd_system_arg("cp -rf %s /data/arbitervmlinux.tmp", filename);

        cmd_system_novty("sleep 1");
        cmd_system_novty("sleep 1; reboot&");

    }
    else {
        vty_out(vty, "Downloading image file success, start upgrade ...%s", VTY_NEWLINE);
        upgrade_image_reboot( save_update, filename);
    }
    return CMD_SUCCESS;

error_ret:
    return CMD_WARNING;
}

ALIAS(_update_image, 
        update_image1_cmd,
        "(update|reset-update) image FILENAME",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n");

ALIAS(_update_image, 
        update_image2_cmd,
        "(update|reset-update) image FILENAME ftp A.B.C.D USERNAME PASSWORD",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n"
        "Indicate use FTP\n"
        "FTP server ipaddress\n"
        "FTP user name\n"
        "FTP user password\n");
ALIAS(_update_image, 
        update_image3_cmd,
        "(update|reset-update) outer image FILENAME",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n");
ALIAS(_update_image, 
        update_image4_cmd,
        "(update|reset-update) outer image FILENAME tftp A.B.C.D",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n"
        "Indicate use tftp\n"
        "tftp server ip address\n");
ALIAS(_update_image, 
        update_image5_cmd,
        "(update|reset-update) outer image FILENAME ftp A.B.C.D USERNAME PASSWORD",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n"
        "Indicate use FTP\n"
        "FTP server ipaddress\n"
        "FTP user name\n"
        "FTP user password\n");

ALIAS(_update_image, 
        update_image6_cmd,
        "(update|reset-update) arbiter image FILENAME",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n");
ALIAS(_update_image, 
        update_image7_cmd,
        "(update|reset-update) arbiter image FILENAME tftp A.B.C.D",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n"
        "Indicate use tftp\n"
        "tftp server ip address\n");
ALIAS(_update_image, 
        update_image8_cmd,
        "(update|reset-update) arbiter image FILENAME ftp A.B.C.D USERNAME PASSWORD",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n"
        "Indicate use FTP\n"
        "FTP server ipaddress\n"
        "FTP user name\n"
        "FTP user password\n");

ALIAS(_update_image, 
        update_image9_cmd,
        "(update|reset-update) stb image FILENAME",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate update standby system, first update inner and outer, then update arbiter\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n");

ALIAS(_update_image, 
        update_image10_cmd,
        "(update|reset-update) stb one-click image FILENAME",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate update standby system\n"
        "Indicate update inner outer arbiter only once reboot\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n");

ALIAS(_update_image, 
        update_image11_cmd,
        "(update|reset-update) stb image FILENAME tftp A.B.C.D",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate update standby system\n"
        "Indicate the update system image\n"
        "Specify update system image file name\n"
        "Indicate use tftp\n"
        "tftp server ip address\n");

ALIAS(_update_image, 
        update_image12_cmd,
        "(update|reset-update) pull image FILENAME tftp A.B.C.D",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate pull system image only\n"
        "Indicate the system image\n"
        "Specify system image file name\n"
        "Indicate use tftp\n"
        "tftp server ip address\n");

ALIAS(_update_image, 
        update_image13_cmd,
        "(update|reset-update) reboot-pull image FILENAME tftp A.B.C.D",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate pull system image, then reboot system\n"
        "Indicate the system image\n"
        "Specify system image file name\n"
        "Indicate use tftp\n"
        "tftp server ip address\n");

ALIAS(_update_image, 
        update_image14_cmd,
        "(update|reset-update) all image FILENAME",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate update inner outer arbiter\n"
        "Indicate the system image\n"
        "Specify system image file name\n");

ALIAS(_update_image, 
        update_image15_cmd,
        "(update|reset-update) all image FILENAME tftp A.B.C.D",
        "Indicate update system image\n"
        "Indicate reset update system image, whole filesystem will be re-build\n"
        "Indicate update inner outer arbiter\n"
        "Indicate the system image\n"
        "Specify system image file name\n"
        "Indicate use tftp\n"
        "tftp server ip address\n");

void gu_cmd_init()
{
    install_element (CONFIG_NODE,     &upgrade_inner_cmd);
    install_element (CONFIG_NODE,     &upgrade_inner1_cmd);
    install_element (CONFIG_NODE,     &upgrade_inner2_cmd);
    install_element (CONFIG_NODE,     &upgrade_outer_cmd);
    install_element (CONFIG_NODE,     &upgrade_outer1_cmd); 
    install_element (CONFIG_NODE,     &upgrade_arbiter_cmd);
    install_element (CONFIG_NODE,     &upgrade_arbiter1_cmd);
    install_element (CONFIG_NODE,     &_update_by_usb_cmd);
    install_element (CONFIG_NODE,     &update_image_cmd);
    install_element (CONFIG_NODE,     &update_image1_cmd);
    install_element (CONFIG_NODE,     &update_image2_cmd);
    install_element (CONFIG_NODE,     &update_image3_cmd);
    install_element (CONFIG_NODE,     &update_image4_cmd);
    install_element (CONFIG_NODE,     &update_image5_cmd);
    install_element (CONFIG_NODE,     &update_image6_cmd);
    install_element (CONFIG_NODE,     &update_image7_cmd);
    install_element (CONFIG_NODE,     &update_image8_cmd);
    install_element (CONFIG_NODE,     &update_image9_cmd);
    install_element (CONFIG_NODE,     &update_image10_cmd);
    install_element (CONFIG_NODE,     &update_image11_cmd);
    install_element (CONFIG_NODE,     &update_image12_cmd);
    install_element (CONFIG_NODE,     &update_image13_cmd);
    install_element (CONFIG_NODE,     &update_image14_cmd);
    install_element (CONFIG_NODE,     &update_image15_cmd);
    install_element (VIEW_NODE,       &show_kernel_version_cmd);
    install_element (ENABLE_NODE,     &show_kernel_version_cmd);
    install_element (VIEW_NODE,       &show_kernel_version1_cmd);
    install_element (ENABLE_NODE,     &show_kernel_version1_cmd);
}

