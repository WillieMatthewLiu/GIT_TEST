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

struct gap_up_mgr{
    int type;
    int fd;
    pthread_t evthread;
    /* Master of threads. */
    struct thread_master *master;
    struct thread *ev_accept;
    struct thread *ev_read;

    struct file_summary *file_sum;
    int file_fd;
};
static struct gap_up_mgr gu_mgr;
static int arbiter_fd = -1;
static int outer_fd = -1;

static struct uprade_packet pkt;
static char ret_buffer[4096];
static int _read(int fd, char *buf, int len){
    return read(fd, buf, len);
}

static int _write(int fd, char *buf, int len){
    return write(fd, buf, len);
}

static void _cleanup(struct gap_up_mgr *mgr){
    unlink( mgr->file_sum->path);
    SCFree(mgr->file_sum);
    mgr->file_sum = NULL;
}

static int up_read(struct thread *t){
    static char filename[256]={0};
    static char filename_tmp[256]={0};
    int len;
    struct gap_up_mgr *mgr = THREAD_ARG(t);
    int fd = THREAD_FD(t);

    mgr->ev_read = NULL;

    memset(&pkt, 0, sizeof(struct uprade_packet));
    len = _read(fd, (char *)&pkt, sizeof(struct uprade_packet));
    if(len <=0){
        close(fd);
        return -1;
    }
    
    switch(pkt.msg_type){
        case UP_MSG_FILE_SUMMARY:
            mgr->file_sum = (struct file_summary *)SCMalloc(sizeof(struct file_summary ));
            memcpy(mgr->file_sum, &pkt.u.file_sum, sizeof(struct file_summary));
            snprintf(filename, 256, "%s", mgr->file_sum->path);
            snprintf(filename_tmp, 256, "%s.XXXXXX", mgr->file_sum->path);
            mgr->file_fd = mkstemp(filename_tmp);
            break;
        case UP_MSG_FILE_TRANS:
            if(!mgr->file_sum){
                _write(fd, "0", 1);
                break;
            }
            {
                struct file_trans *trans = &pkt.u.trans;
                if(trans->len){
                    if(write(mgr->file_fd, trans->data, trans->len) < 0){
                        printf("write error %s", strerror(errno));
                        _cleanup(mgr);
                    }
                    _write(fd, "1", 1);
                }
                if(!trans->frame){
                    char cmd[256]={};
                    char buf[256]={};

                    printf("file tracs end.\n");
                    sync();
                    close(mgr->file_fd);
                    unlink(filename);
                    link(filename_tmp, filename);
                    sync();
                    unlink(filename_tmp);
                    snprintf(cmd, 256, "/usr/bin/md5sum %s", filename);
                    
                    cmd_system_getout(cmd, buf, 256);
                    if(strncmp(buf, mgr->file_sum->md5_sum, 32) != 0){
                        _cleanup(mgr);
                    }else{
                    }
                    _write(fd, "1", 1);
                }
                
            }
            break;
        case UP_MSG_DO_UPGRADE:
            switch(mgr->file_sum->type){
                case UP_FILE_TYPE_RPM:
                    upgrade_rpm(filename, 0);
                    _write(fd, "1", 1);
                    break;
                case UP_FILE_TYPE_CA:
                    upgrade_file(filename, CA_FULLNAME, 0);
                    _write(fd, "1", 1);
                    break;
                case UP_FILE_TYPE_CERT:
                    if(upgrade_check_cert(filename) < 0){
                        _write(fd, "cert veriy fail, please update ca first.", strlen("cert veriy fail, please update ca first.")+1);
                    }
                    else{
                        upgrade_file(filename, CERT_FULLNAME, 0);
                        _write(fd, "1", 1);
                    }
                    break;
                case UP_FILE_TYPE_KEY:
                    if(upgrade_check_privatekey(filename) < 0){
                        _write(fd, "key verify fail, please update cert first.", strlen("key verify fail, please update cert first.")+1);
                    }
                    else{
                        upgrade_file(filename, CERT_FULLNAME, 0);
                        _write(fd, "1", 1);
                    }
                    break;
                case UP_FILE_TYPE_IMAGE:
                    //upgrade_image_reboot(1, filename);
                    _write(fd, "1", 1);
                    break;
                case UP_FILE_TYPE_IMAGE_RST:
                    //upgrade_image_reboot(0, filename);
                    _write(fd, "1", 1);
                    break;
                default:
                    break;
            }
            _cleanup(mgr);
            break;
        case UP_MSG_RUN_CMD:
            {
                FILE *fp;
                char cmd[1024];
                snprintf(cmd, 1024, "vtysh %s", pkt.u.data);

                fp = popen(cmd, "r");
                if(NULL == fp)
                {
                    _write(fd, "run failure", 11);
                }else{
                    len = fread(ret_buffer, 1, 4096, fp);
                    pclose(fp);
                    #ifdef DEBUG
                    fprintf(stdout, "%s", ret_buffer);
                    #endif
                    if(len)
                        _write(fd, ret_buffer, strlen(ret_buffer));
                    else{
                        memset(ret_buffer, 0, 5);
                        _write(fd, ret_buffer, 3);
                    }
                }
            }
            break;
        default:
            break;
    }

    mgr->ev_read = thread_add_read(mgr->master, up_read, mgr, fd);

    return 0;

}

static int up_accept(struct thread *t){
    int sock;
    int on =1;
    struct sockaddr_in sin;
    socklen_t sock_len = sizeof(sin);
    struct gap_up_mgr *mgr = THREAD_ARG(t);
    int fd = THREAD_FD(t);

    mgr->ev_accept = NULL;
    
    sock = accept(fd, (struct sockaddr *)&sin, &sock_len);
    if(sock < 0)
        return -1;
    printf("new client %d\n", sock);
    set_nonblocking(sock);
    setsockopt (sock, IPPROTO_TCP, TCP_NODELAY, 
		    (char *) &on, sizeof (on));
    mgr->fd = sock;
    
    mgr->ev_read= thread_add_read(mgr->master, up_read, mgr, sock);
    
    mgr->ev_accept = thread_add_read(mgr->master, up_accept, mgr, fd);

    return sock;
}

static int
_serv_sock_family (const char* ip_str, unsigned short port)
{
    int fd;
    struct sockaddr_in addr;
    int on = 1;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd < 0)
    {
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof(on));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on, sizeof(on));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_str);
    addr.sin_port = htons(port);

    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    listen(fd, 5);

    set_nonblocking(fd);

    return fd;
}


int up_connect(const char *path, const char *ip_str, uint16_t port )
{
    int sock;
    struct sockaddr_in addr;
    struct gap_up_mgr *mgr = &gu_mgr;

    if(path){
        mgr->fd = open(path, O_RDWR);
        if(mgr->fd > 0)
            return mgr->fd;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_str);
    addr.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return -1;
    }

    set_nonblocking(sock);
    return sock;

}

static void *upgrade_thread(void* args)
{
    struct thread t;
    struct gap_up_mgr *mgr = (struct gap_up_mgr *)args;

    while(thread_fetch(mgr->master, &t)){
        thread_call(&t);
    }

    return NULL;
}
int upgrade_init(int board, const char *path, const char *ip_str, uint16_t port )
{
    int fd;

    gu_mgr.master = thread_master_create ();
    
    if(path){
        fd = open(path, O_RDWR);
        if(fd >0){
            gu_mgr.ev_read = thread_add_read(gu_mgr.master, up_read, &gu_mgr, fd);
            return 0;
        }
    }

    if(ip_str){
        gu_mgr.type = 1;
        if(board != BOARDTYPE_IN){
            fd = _serv_sock_family(ip_str, port);
            if(fd > 0){
                gu_mgr.ev_accept = thread_add_read(gu_mgr.master, up_accept, &gu_mgr, fd);
            }
        }
    }

    pthread_create(&gu_mgr.evthread, NULL, upgrade_thread, &gu_mgr);
#ifdef USER_MEM_ALLOC
    ThreadMemInit("", gu_mgr.evthread);
#endif

    return 0;
}


int send_summary(int fd, int type, 
    const char *path){
    int ret = 0;
    struct file_summary *sum = &pkt.u.file_sum;
    struct stat fstat;
    char cmd[256];

    if(stat(path, &fstat) <0)
        return -1;

    memset(&pkt, 0, sizeof(pkt));
    
    pkt.msg_type = UP_MSG_FILE_SUMMARY;
    sum->type = type;
    sum->size = fstat.st_size;
    strcpy(sum->path, path);

    snprintf(cmd, 256, "/usr/bin/md5sum %s", path);
    cmd_system_getout( cmd, sum->md5_sum, 32);

    if(_write(fd, (char *)&pkt, sizeof(struct file_summary) + sizeof(int)) < 0){
        ret = -1;
    }
    
    return ret;
}

int copy_file(int fd, int type, 
    const char *path)
{
    int ret = 0;
    int filefd;
    int len, count, m;
    char buf[128];
    struct stat fstat;

    if(stat(path, &fstat) <0)
        return -1;

    filefd = open(path, O_RDONLY);

    m = fstat.st_size % MAX_TRANS_LEN;

    memset(&pkt, 0, sizeof(pkt));
    pkt.msg_type = UP_MSG_FILE_TRANS;
    for(count = 0; count < fstat.st_size - m; ){
        len = read(filefd, pkt.u.trans.data, MAX_TRANS_LEN);
        pkt.u.trans.len = len;
        ++pkt.u.trans.frame;

        if(_write(fd, (char *)&pkt, len + 12) < 0){
            ret = -1;
            goto END;
        }
        count += len;
        _read(fd,buf, 128);
    }
    if(m){
        len = read(filefd, pkt.u.trans.data, MAX_TRANS_LEN);
        pkt.u.trans.len = len;
        if(_write(fd, (char *)&pkt, len+12) < 0){
            ret = -1;
            goto END;
        }
        _read(fd,buf, 128);
    }
    fprintf(stdout, "frame = %d\n", pkt.u.trans.frame);
    pkt.u.trans.frame = 0;
    pkt.u.trans.len = 0;
    _write(fd, (char *)&pkt, 12);
    _read(fd,buf, 128);
END:
    close(filefd);
    return ret;
}

int _upgrade(fd)
{
    memset(&pkt, 0, sizeof(pkt));
    pkt.msg_type = UP_MSG_DO_UPGRADE;
    if(_write(fd, (char *)&pkt, sizeof(int)) < 0){
        return -1;
    }

    return 0;
}

/**
    do upgrade
    @param int board_type
    @param int type file type
    @param const char * filename
*/
char *do_upgrade(int board_type, int type, const char * filename)
{
    vector v = vector_init(2);
    char *cmd1 = "configure terminal";
    char cmd2[256]={0};

    switch(type){
        case UP_FILE_TYPE_CA:
            snprintf(cmd2, 256, "upgrade cacrt %s tftp 192.168.0.2", filename);
            break;
        case UP_FILE_TYPE_CERT:
            snprintf(cmd2, 256, "upgrade crt %s tftp 192.168.0.2", filename);
            break;
        case UP_FILE_TYPE_KEY:
            snprintf(cmd2, 256, "upgrade key %s tftp 192.168.0.2", filename);
            break;
        case UP_FILE_TYPE_RPM:
            snprintf(cmd2, 256, "upgrade rpm %s tftp 192.168.0.2", filename);
            break;
        default:
            return "Unkown file type.";
    }
        
    vector_set(v, cmd1);
    vector_set(v, cmd2);
    return do_cmdv(board_type, v, 10);

}

char * do_cmd(int board_type, char *cmd){
    int fd;
    
    if(board_type == BOARDTYPE_ARBITER){
        if(arbiter_fd < 0)
            arbiter_fd = up_connect(TO_ARTIBER_DEV, "192.168.0.1", UPGRADE_PORT);
        fd = arbiter_fd;
    }else if(board_type == BOARDTYPE_OUT){
        if(outer_fd < 0)
            outer_fd = up_connect(TO_OUTER_DEV, "192.168.0.3", UPGRADE_PORT);
        fd = outer_fd;
    }else{
        fd = -1;
    }
    if(fd < 0){
        goto END;
    }

    memset(&pkt, 0, sizeof(struct uprade_packet));

    pkt.msg_type = UP_MSG_RUN_CMD;
    snprintf(&pkt.u.data[0], MAX_TRANS_LEN, "-c '%s' ", cmd);

    _write(fd, &pkt, sizeof(pkt));

    _read(fd,  ret_buffer, 4096);
    return ret_buffer;
END:
    if(board_type == BOARDTYPE_ARBITER){
        if(arbiter_fd > 0)
            close( arbiter_fd);
        arbiter_fd = -1;
    }else if(board_type == BOARDTYPE_OUT){
        if(outer_fd > 0)
            close(outer_fd);
        outer_fd = -1;
    }
    return NULL;
}

char *do_cmdv(int board_type, vector v, int timeout){
    
    int i, len = 0;
    int fd;
    int ret;
    fd_set r_fd;
    struct timeval tv={10,0};
    
    if(board_type == BOARDTYPE_ARBITER){
        if(arbiter_fd < 0)
            arbiter_fd = up_connect(TO_ARTIBER_DEV, "192.168.0.1", UPGRADE_PORT);
        fd = arbiter_fd;
    }else if(board_type == BOARDTYPE_OUT){
        if(outer_fd < 0)
            outer_fd = up_connect(TO_OUTER_DEV, "192.168.0.3", UPGRADE_PORT);
        fd = outer_fd;
    }else{
        fd = -1;
    }
    if(fd < 0){
        goto END;
    }
    pkt.msg_type = UP_MSG_RUN_CMD;
    for(i = 0; i < vector_active(v); i++){
        len = snprintf(&pkt.u.data[len], MAX_TRANS_LEN-len, "-c '%s' ", (char *)vector_slot(v,i));
    }

    if(len >= MAX_TRANS_LEN){
        return "command to length";
    }
#ifdef DEBUG
    fprintf(stdout, "%s\n", pkt.u.data);
#endif
    _write(fd, &pkt, sizeof(pkt));

    FD_ZERO(&r_fd);
    FD_SET(fd, &r_fd);
    tv.tv_sec = timeout;
    if(timeout)
        ret = select(fd+1, &r_fd, NULL, NULL, &tv);
    else
        ret = select(fd+1, &r_fd, NULL, NULL, NULL);
    switch(ret){
        case 0:
            return "execute command timeout.";
        case -1:
            return "FETAL ERROR.";
        default:
            if(FD_ISSET(fd, &r_fd)){
                len = _read(fd,  ret_buffer, 4096);
                return ret_buffer;
            }
    }
    
    return ret_buffer;
    
END:
    if(board_type == BOARDTYPE_ARBITER){
        if(arbiter_fd > 0)
            close( arbiter_fd);
        arbiter_fd = -1;
    }else if(board_type == BOARDTYPE_OUT){
        if(outer_fd > 0)
            close(outer_fd);
        outer_fd = -1;
    }
    return NULL;
}


void up_add_timer(int (*func) (struct thread *), void *args, long tm)
{
    thread_add_timer_msec(gu_mgr.master, func, args, tm);
}
