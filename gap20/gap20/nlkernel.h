#pragma once

#include "nlkernelmsg.h"

evutil_socket_t nlkernel_init();
int nlkernel_free();

// 向内核发送一条消息
int nlkernel_sendmsg(struct nl_kernel_msg *msg);

// 向网络发送一个数据包
int nlkernel_sendpkt(const char *ethname, const void *packet, size_t len);

// 向内核索要某个会话的用户ID和MAC地址
uint32_t nlkernel_getuidbyaddr(uint32_t srcip, uint16_t srcport, uint32_t localip, uint16_t localport, uint8_t *mac);

// 向内核添加一条“加密通道”，FTP 主动模式时使用
uint32_t nlkernel_addenc(uint32_t srcip, uint16_t srcport, uint32_t localip, uint16_t localport, uint32_t uid);

// 清空内核所有规则
uint32_t nlkernel_clearconfig();

// 启用ARP规则
void nl_arp_enable();

// 禁用ARP规则
void nl_arp_disable();

// 启用内核加密功能
void nlkernel_encrypt_enable();

// 禁用内核加密功能
void nlkernel_encrypt_disable();

