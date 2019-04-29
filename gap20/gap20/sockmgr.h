#pragma once

struct connectionmgr;
struct sessionmgr;


/*
* 设置连接/会话管理器空闲时的回调函数
* args，自定义参数
*/
typedef void(*TIMER_CB)(void *args);


/*
* accept到有效fd后，触发此回调函数
* fd，客户端接进来的socketfd
* cliaddr、cliaddrlen，accept的标准参数
* args，自定义参数
*/
typedef void(*LISTENER_CB)(evutil_socket_t fd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args);


/*
* connect成功/失败后，触发此回调函数
* fd，连接成功后，对应的socket；fd == -1，表示服务器连接失败
* args，自定义参数
*/
typedef void(*CONNECT_CB)(evutil_socket_t fd, void *args);


/*
* 创建一个新的连接管理器，返回对应的结构指针
*/
struct connectionmgr* connmgr_new();

/*
* 设置会话管理器的定时器回调
* tv，待设置的超时值
* mgr，在哪个会话管理器上设置
* timercb，对应的回调函数
* args，自定义参数
*/
int connmgr_settimercb(struct connectionmgr *mgr, struct timeval *tv, TIMER_CB timercb, void *args);

/*
* 打开一个端口进行监听
* mgr，在哪个连接管理器上运行
* localaddr，本地IP地址，点分隔IPV4地址字符串
* localport，本地端口号
* cb，对应LISTENER_CB，成功对客户端accept后触发
* args，自定义参数
* 返回值，成功返回0，失败返回非0
*/
int connmgr_addlistener(struct connectionmgr *mgr, const char *localaddr, uint16_t localport, LISTENER_CB cb, void *args);

evutil_socket_t new_udp_service(const char *localaddr, uint16_t localport, void *agrs);

int tcpudp_port_test(const char *ip, uint16_t port, int type);


/*
* 移除对某个端口的监听
* mgr，在哪个连接管理器上运行
* localaddr，本地IP地址，点分隔IPV4地址字符串
* localport，本地端口号
* 返回值，成功返回0，失败返回非0
*/
int connmgr_removelistener(struct connectionmgr *mgr, const char *localaddr, uint16_t localport);

/*
* 向指定IP地址、端口建立连接
* mgr，在哪个连接管理器上运行
* dstaddr，目标IP地址，点分隔IPV4地址字符串
* dstport，目标端口号
* timeout，连接超时设置
* cb，对应CONNECT_CB，对目标IP连接成功/失败后触发
* args，自定义参数
* 返回值，成功返回0，失败返回非0
*/
int connmgr_addconnect(struct connectionmgr *mgr, const char *dstaddr, uint16_t dstport, struct timeval *timeout, CONNECT_CB cb, void *args);

/*
* 向指定IP地址、端口建立连接，阻塞方式
* dstaddr，目标IP地址，点分隔IPV4地址字符串
* dstport，目标端口号
* 返回值，成功返回对应的socket，失败返回-1
*/
evutil_socket_t connmgr_syncconnect(const char *dstaddr, uint16_t dstport);

/*
* 关闭连接管理器
* mgr，要关闭的连接管理器
*/
void connmgr_free(struct connectionmgr *mgr);





/*
* 会话有数据到达/网络异常时，会触发此函数
* buff，len，对应的数据buffer及长度
* args，自定义参数
*/
typedef void(*ONDATA_CB)(const void *buff, size_t len, void *args);
typedef void(*ONUDPDATA_CB)(const void *buff, size_t len, evutil_socket_t svrfd, struct sockaddr *cliaddr, socklen_t cliaddrlen, void *args);
typedef void(*UDP_TIME_OUT_CB)(struct sessionmgr *mgr, evutil_socket_t svrfd, void *args);
/*
* 会话数据发完以后，会触发此函数
* args，自定义参数
*/
typedef void(*ONWRITE_CB)(size_t restlen, void *args);

/*
* 创建一个会话管理器
* 返回值，返回对应的会话管理器
*/
struct sessionmgr* sessionmgr_new();

struct sessionmgr* sessionmgr_current();

/*
* 设置当前会话管理器的优先级（SCHED_RR）
* 返回值，成功返回0，失败返回非0
*/
int sessionmgr_setpriority(struct sessionmgr *mgr, int level);

/*
* 将当前会话管理器绑到某个CPU上
* 返回值，成功返回0，失败返回非0
*/
int sessionmgr_setcpu(struct sessionmgr *mgr, int cpu);

/*
* 获取当前会话ID（从0开始，每ssmgr_new一个每次加1）
* 返回值，返回对应的会话管理器
*/
int sessionmgr_getid(struct sessionmgr *mgr);

/*
* 获取当前管理器线程的最后一次活动时间
*/
int sessionmgr_getlivetime(struct sessionmgr *mgr);

/*
* 设置会话管理器的定时器回调
* mgr，在哪个会话管理器上设置
* tv，待设置的超时值
* timercb，对应的回调函数
* args，自定义参数
*/
int sessionmgr_settimercb(struct sessionmgr *mgr, struct timeval *tv, TIMER_CB timercb, void *args);

/*
* 向会话管理器添加一个fd进行管理
* mgr，在哪个会话管理器上运行
* fd，要管理的fd
* datacb，数据到达/网络异常时的回调函数
* writecb，“待发送缓冲区”的数据发完后的回调函数
* tv，接收数据的超时设置，允许传空，表示不设置超时值
* args，自定义参数
* 返回值，成功返回0，失败返回非0
*/
int sessionmgr_fdadd(struct sessionmgr *mgr, evutil_socket_t fd, ONDATA_CB datacb, ONWRITE_CB writecb, struct timeval *tv, void *args);
int sessionmgr_fdaddlock(struct sessionmgr *mgr, evutil_socket_t fd, ONDATA_CB datacb, ONWRITE_CB writecb, struct timeval *tv, void *args, int lock);

int sessionmgr_udpfdadd(struct sessionmgr *mgr, evutil_socket_t fd, ONUDPDATA_CB datacb, UDP_TIME_OUT_CB timeoutcb, struct timeval *tv, void *agrs);
/*
* 为一个会话管理器内的fd重新设置超时
* mgr，fd隶属的会话管理器
* fd，要设置的fd
* tv，接收数据的超时设置
* 返回值，成功返回0，失败返回非0
*/
int sessionmgr_fdtimeout(struct sessionmgr *mgr, evutil_socket_t fd, struct timeval *tv);

/*
* 向会话管理器的某个fd发送数据，注意不会立即发送，而是将数据放到框架的“待发送缓冲区”内
* mgr，fd隶属的会话管理器
* fd，要发送数据的fd
* buff，len，要发送的数据及长度
* 返回值，成功返回待发送缓冲区愉的数据大小，失败-1
*/
int sessionmgr_fdsend(struct sessionmgr *mgr, evutil_socket_t fd, const void *buff, size_t len);
int sessionmgr_fdsend_buff(struct sessionmgr *mgr, evutil_socket_t fd, struct evbuffer *buff);

/*
* 暂停/恢复FD的读行为
* mgr，fd隶属的会话管理器
* fd，要发送数据的fd
* window，设置fd能读取数据的上限，0表示不再读了，-1表示不控制
* 返回值，成功返回0，失败返回非0
*/
int sessionmgr_fdwindow(struct sessionmgr *mgr, evutil_socket_t fd, int window);
int sessionmgr_fdwindow_all(struct sessionmgr *mgr, int window, evutil_socket_t *except_fds, int count);


/*
* 向会话管理器的某个fd发送数据
* mgr，fd隶属的会话管理器
* fd，要发送数据的fd
* lock，1：lock    0：unlock
* 返回值，成功返回0，失败返回非0
*/
int ssmgr_fdlock(struct sessionmgr *mgr, evutil_socket_t fd, int lock);

/*
* 关闭某个会话管理器中的fd
* mgr，fd隶属的会话管理器
* fd，要关闭的fd
* buff，len，要发送的数据及长度
* 返回值，成功返回0，失败返回非0
*/
int sessionmgr_fdclose(struct sessionmgr *mgr, evutil_socket_t fd);

/*
* 关闭指定的会话管理器
* mgr，要关闭的会话管理器
*/
void sessionmgr_free(struct sessionmgr *mgr);

/*
* 阻塞方式发数据
* fd，socket对应的句柄
* buff，待发送的数据
* len，数据长度
* 返回值，成功返回0，失败返回非0
*/
int socket_syncsend(evutil_socket_t fd, const void *buff, size_t len);

int socket_syncrecv(evutil_socket_t fd, const void *buff, size_t len);
