#include <ctype.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sched.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <linux/icmp.h>
#include "app_common.h"
#include "card_config.h"
#include "command.h"
#include "thread.h"
#include "vty.h"

//#include "proto.h"
#include "card_ssl_client.h"
#include "card_crypt.h"
#include "card_route.h"
#include "card_common.h"

#define USE_THREAD_RCV_PKT 0

#define RCV_BUF_SIZE  (65*1024)
#define UPGRADE_BUF_LEN (512)
#define FILE_NAME_LEN (256)
char upgrade_file_name[FILE_NAME_LEN];

struct jobmgr *g_jobmgr = NULL;
static volatile int g_dropall = 0;

/* card support two interface eth0 and eth1 */
char card_intf[2][32] = {"eth0", "eth1"};
static int g_eth0fd = -1;
static int g_eth1fd = -1;
static struct sockaddr_ll g_eth0_sl;
static struct sockaddr_ll g_eth1_sl;

static char *vty_addr = "127.0.0.1";
static int vty_port = 2601;
struct thread_master * master;  

#define APP_DEFAULT_CONFIG "gap20.conf.def"
char config_default[] = SYSCONFDIR APP_DEFAULT_CONFIG;

void ssl_disconnect_gap();

void print_dump(uint8_t *data, int len, char *msg)
{
    int i;
    if(msg)
        SCLogInfo("\n%s:", msg);
    printf("length: %d\n", len);
    for(i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
        if(((i+1) % 16) == 0)
            printf("\n");
    }
     printf("\n");
}

void save_config(char *cmd)
{
	int sockfd;
	struct sockaddr_in    servaddr; 
	char buf[512] = {0};
	int length;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		SCLogError( "Creating socket failed.");
		return;
	}

	memset(&servaddr, 0, sizeof(servaddr));  
	servaddr.sin_family = AF_INET;  
	servaddr.sin_port = htons(vty_port);  
	servaddr.sin_addr.s_addr = inet_addr(vty_addr);
	if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{  
		SCLogError( "can not connect to server: %s:%d, error string: %s", 
				inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), strerror (errno));
		close(sockfd);
		return;
	}  

	if(send(sockfd, cmd, strlen(cmd) + 1, 0) < 0)
	{  
		SCLogError( "send cmd:  %s error,  %s(errno: %d)\n", cmd, strerror(errno), errno); 
		close(sockfd);
		return;  
	}
	length = recv(sockfd, buf, 512, 0);
	if(length < 0)
		SCLogError( "recv error,  error string: %s(errno: %d)\n", strerror(errno), errno); 
	//printf("%d\n", length);
	//printf("%s\n", buf);
	close(sockfd);
}

int config_py1(struct Win2cardParam *param)
{
	char cmd[128] = {0};
	struct in_addr phy1ip, mask;// gapip;gateway;
	struct sockaddr_in sin;
	struct ifreq ifr;

	phy1ip.s_addr = param->phy1ip;
	mask.s_addr = param->mask;
	
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, card_intf[0], sizeof(ifr.ifr_name));
	if(ioctl(g_eth0fd, SIOCGIFHWADDR, &ifr) < 0)
		SCLogError( "ioctl failed, %s\n", strerror(errno));
	/*printf("mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n",  
					(unsigned char)ifr.ifr_hwaddr.sa_data[0],  
					(unsigned char)ifr.ifr_hwaddr.sa_data[1],  
					(unsigned char)ifr.ifr_hwaddr.sa_data[2],  
					(unsigned char)ifr.ifr_hwaddr.sa_data[3],  
					(unsigned char)ifr.ifr_hwaddr.sa_data[4],  
					(unsigned char)ifr.ifr_hwaddr.sa_data[5]);*/
	if(memcmp(param->mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6))
	{
		snprintf(cmd, sizeof(cmd), "ifconfig %s down", card_intf[0]);
		if(system(cmd) == -1)
			goto error;
		
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ifconfig %s hw ether %02X:%02X:%02X:%02X:%02X:%02X", card_intf[0], \
			                                                                      param->mac[0], param->mac[1], param->mac[2], \
													param->mac[3], param->mac[4], param->mac[5]);
		if(system(cmd) == -1)
			goto error;

		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ifconfig %s up", card_intf[0]);
		if(system(cmd) == -1)
			goto error;
	}

	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, card_intf[0], sizeof(ifr.ifr_name));
	ioctl(g_eth0fd, SIOCGIFADDR, &ifr);
	memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
	if(sin.sin_addr.s_addr != param->phy1ip)
	{
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ifconfig %s %s", card_intf[0], inet_ntoa(phy1ip));
		if(system(cmd) == -1)
			goto error;

		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ifconfig %s netmask %s", card_intf[0], inet_ntoa(mask));
		if(system(cmd) == -1)
			goto error;
	}
	
	return 0;

error:
	SCLogError( "win to card param error!\n");
	return -1;
}

int set_sys_time(const char *timestr)
{
#define TIME_LEN 64
	char sys_time[TIME_LEN] = {0};
	char result[256] = {0};
	char *pos = sys_time;

	/*copy YYYYMMDD */
	memcpy(pos, timestr, 8);
	pos += 8;
	*pos++ = ' ';

	/*copy hh */
	memcpy(pos, timestr + 8, 2);
	pos += 2;
	*pos++ = ':';
	
	/*copy mm */
	memcpy(pos, timestr + 10, 2);
	pos += 2;
	*pos++ = ':';
	
	/*copy ss */
	memcpy(pos, timestr + 12, 2);
	pos += 2;
	*pos = 0;

	SCLogInfo("sys_time: %s\n", sys_time);
	get_result_by_system(result, sizeof(result), "date -s \"%s\" && hwclock -w", sys_time);
	if(strstr(result, "invalid date"))
	{
		SCLogError( "set system time failed\n");
		return -1;
	}
	else
	{
		return 0;
	}
}

int upgrade_check_rpm(char *file)
{
	FILE *fp_read = NULL;
	char buf_t[UPGRADE_BUF_LEN] = {0};

	sprintf(buf_t, "rpm -qpi %s%s | grep Architecture | cut -d ' ' -f 2", "/tmp/", file);
	fp_read = popen(buf_t, "r");
	if(fp_read == NULL) 
	{
		SCLogError( "Upgrade %s Failed\n", file);
		return -1;
	}

	if(fgets(buf_t, UPGRADE_BUF_LEN, fp_read) == NULL) 
	{
		SCLogError( "Not found %s Architecture\n", file);
		pclose(fp_read);
		fp_read = NULL;
		return -1;
	}

	if((strncmp("kee", buf_t, 3) == 0) || (strncmp("cortexa8hf_vfp_neon", buf_t, 19) == 0)) 
	{
		pclose(fp_read);
		fp_read = NULL;
		return 0;
	}
	pclose(fp_read);
	fp_read = NULL;
	SCLogError( "Invalid Architecture %s\n", buf_t);
	return -1;
}

int upgrade_check_privatekey(const char* key)
{
    int ret;
    SSL_CTX *ctx;
    
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_method());
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    ret = SSL_CTX_load_verify_locations(ctx, SSL_DEFAULT_CACERT, NULL);
    if (ret != 1)
    {
        return -1;
    }
    ret = SSL_CTX_use_certificate_file(ctx, SSL_DEFAULT_MYCERTF, SSL_FILETYPE_PEM);
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

int upgrade_check_cert(const char* cert)
{
    char buf[UPGRADE_BUF_LEN];
    char cmd[UPGRADE_BUF_LEN];
    /* verify crt with ca */
    snprintf(cmd, UPGRADE_BUF_LEN, "openssl verify -CAfile %s /tmp/%s", SSL_DEFAULT_CACERT, cert);
    if(cmd_system_getout(cmd, buf, UPGRADE_BUF_LEN) <= 0 
        || NULL == strstr(buf, "OK"))
    {
        return -1;
    }
    return 0;
}

int upgrade_sync_rpm_to_update_partition(char *file)
{
	FILE *fp_read = NULL;
	char buf[UPGRADE_BUF_LEN] = {0};

	sprintf(buf, "cd /update && /usr/lib/rpm/rpm2cpio %s%s | cpio -diu 2>&1 && sync", "/tmp/", file);
	fp_read = popen(buf, "r");
	if(fp_read == NULL) 
	{
		SCLogError( "Upgrade %s Failed\n", file);
		return -1;
	}

	while (fgets(buf, UPGRADE_BUF_LEN, fp_read) != NULL) 
	{
		if(strstr(buf, "cannot") != NULL) 
		{
			SCLogError( "%s\n", buf);
			pclose(fp_read);
			fp_read = NULL;
			return -1;
		}
	}
	pclose(fp_read);
	fp_read = NULL;
	SCLogInfo("Upgrade %s success\n", file);
	return 0;
}

int upgrade_rpm(char *file)
{
	int ret;
	
	if(upgrade_check_rpm(file) < 0)
		return -1;

	if(upgrade_sync_rpm_to_update_partition(file) < 0)
			return -1;
	
	cmd_system_novty("sync");
	
	return 0;
}

int upgrade_file(char *file_src, char *file_dst)
{
	FILE *fp_read = NULL;
	char buf[UPGRADE_BUF_LEN] = {0};

	sprintf(buf, "ls %s%s 2>&1 && /bin/cp -rf %s%s %s 2>&1", 
		"/tmp/", file_src,
		"/tmp/", file_src, file_dst);
	fp_read = popen(buf, "r");
	if(fp_read == NULL) 
	{
		SCLogError( "Upgrade %s Failed\n", file_src);
		return -1;
	}
	while (fgets(buf, UPGRADE_BUF_LEN, fp_read) != NULL) 
	{
		if(strstr(buf, "cannot") != NULL) 
		{
			SCLogError( "%s\n", buf);
			pclose(fp_read);
			fp_read = NULL;
			return -1;
		}
	}
	pclose(fp_read);
	fp_read = NULL;
	SCLogInfo("Upgrade %s success\n", file_src);

	cmd_system_novty_arg("/bin/rm -rf /tmp/%s", file_src);
	return 0;
}

int upgrade_encrypt_keyfile(char *file_src)
{
	if(cmd_system_novty_arg("load_rsa_key prikey %s 2>&1 ", file_src))
		return -1;

	cmd_system_novty_arg("/bin/rm -rf %s", file_src);
	return 0;
}

int upgrade_sync_file_to_update_partition(char *file)
{
	FILE *fp_read = NULL;
	char buf[UPGRADE_BUF_LEN];

	memset(buf, 0, sizeof(buf));

	/* copy file to update flash partition */
	sprintf(buf, "sync");
	fp_read = popen(buf, "r");
	if(fp_read == NULL) {
		SCLogError("Upgrade %s Fail", file);
		return -1;
	}

	while (fgets(buf, UPGRADE_BUF_LEN, fp_read) != NULL) {
		if(strstr(buf, "cannot") != NULL) {
			SCLogError( "%s", buf);
			pclose(fp_read);
			fp_read = NULL;
			return CMD_ERR_INCOMPLETE;
		}
	}
	pclose(fp_read);
	fp_read = NULL;

	return CMD_SUCCESS;
}

int upgrade_fw(char *file_name)
{
	//cmd_system_novty("echo close > /var/run/dog_fifo");
	
	if(strstr(file_name, ".rpm") != NULL)
	{
		 if(upgrade_rpm(file_name) < 0)
		 	return -1;
		 
		 cmd_system_novty("reboot");
	}
	else if(strstr(file_name, "crtkey.bin") != NULL)
	{
		if(g_jobmgr->session->connected)
			ssl_disconnect_gap();
		
		cmd_system_novty_arg("cd /tmp && unzip %s", file_name);
		
		if(!access("/tmp/ca.crt", F_OK))
		{
			upgrade_file("ca.crt", SSL_DEFAULT_CACERT);
			upgrade_sync_file_to_update_partition("ca.crt");
		}
		if(!access("/tmp/gap.crt", F_OK))
		{
			if(upgrade_check_cert("gap.crt") < 0 )
			{
				SCLogError( "cert verify fail. please upgrade ca.crt first.");
				return -1;
			}
			upgrade_file("gap.crt", SSL_DEFAULT_MYCERTF);
			upgrade_sync_file_to_update_partition("gap.crt");
		}
		if(!access("/tmp/gap.key", F_OK))
		{
			if(upgrade_check_privatekey("/tmp/gap.key") < 0)
			{
				SCLogError( "key verify fail. please upgrade cert first.");
				return -1;
			}
			upgrade_encrypt_keyfile("/tmp/gap.key");
		}
		
		cmd_system_novty_arg("cd ~/");
	}

	cmd_system_novty_arg("/bin/rm -rf /tmp/%s", file_name);
	//cmd_system_novty("echo open > /var/run/dog_fifo");
	return 0;
}

void icmp_reply(unsigned char *buf, unsigned length)
{
	struct iphdr *iph = NULL;
	struct icmphdr *icmph = NULL;
	unsigned int addr_temp;
	int send_len;
	unsigned short len;
	unsigned char mac_temp[6];

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	icmph  = (struct icmphdr *)(buf + sizeof(struct ethhdr) + iph->ihl*4);

	memcpy(mac_temp, buf, 6);
	memcpy(buf, buf + 6, 6);
	memcpy(buf + 6, mac_temp, 6);
	
	addr_temp = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = addr_temp;
	
	icmph->type = ICMP_ECHOREPLY;
	icmph->checksum = 0;
	/*len = length - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr);
	zero_to_space((char *)(icmph + 1), len);

	len = length - sizeof(struct ethhdr) - sizeof(struct iphdr);
	icmph->checksum = cal_cksum((unsigned short *)icmph, len);*/
	len = sizeof(struct icmphdr) + strlen(ICMP_PARAM_TAG) + 3; 
	memcpy((char *)icmph + len, "OK", 2);
	len += 2;
	icmph->checksum = cal_cksum((unsigned short *)icmph, len);

	len += iph->ihl*4;
	iph->tot_len = htons(len);
	iph->check = 0;
	iph->check = cal_cksum((unsigned short *)iph, len);
	len += sizeof(struct ethhdr);
	buf[len] = 0;
	/*printf("string: %s\n", buf + 14 + iph->ihl*4 + 8);
	printf("%s(): %d, len = %d\n", __func__, __LINE__, len);
	for(int i = 0; i < len; i++)
	{
		printf("%02x ", buf[i]);
		if((i+1) % 8 == 0)
			printf("\n");
	}
	printf("\n");*/
	send_len = sendto(g_eth1fd, buf, len, 0, (struct sockaddr *)&g_eth1_sl, sizeof(g_eth1_sl));
	if(send_len < 0)
	{
		SCLogError( "sendto error: %s, %d\n", strerror(errno), __LINE__);
	}
}

int icmp_parse(unsigned char *buf, int length)
{
	struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	struct icmphdr *icmph = (struct icmphdr *)(buf + sizeof(struct ethhdr) + iph->ihl*4);
	char *data = NULL;
	char tag = 0;
	int send_len, len;
	char cmd[256] = {0};
	
	if(icmph->type != ICMP_ECHO)
		return 1;

	data = (char *)(icmph + 1);
	if(memcmp(data, ICMP_PARAM_TAG, strlen(ICMP_PARAM_TAG)) != 0)
		return 1;
	
	len = length - (sizeof(struct ethhdr) + iph->ihl*4 + sizeof(struct icmphdr) + strlen(ICMP_PARAM_TAG) + 1);
	data += (strlen(ICMP_PARAM_TAG) + 1);
	tag = *data;
	//printf("tag: %c\n", tag);
	
	data += 2;
	len -= 2;
	
	switch(tag)
	{
		case '0':
			//printf("gapip: %s\n", data);
			g_jobmgr->param.gapip = inet_addr(data);
			snprintf(cmd, sizeof(cmd), "route add %s %s", data, card_intf[0]);
			cmd_system_novty(cmd);
			break;
			
		case '1':
			space_to_zero(data, len);
			if(ConverMacAddressStringIntoByte(data, g_jobmgr->param.mac) == NULL)
			{
				//zero_to_space(data, len);
				return -1;
			}
			data += (strlen(data) + 1);
			
			g_jobmgr->param.phy1ip = inet_addr(data);
			data += (strlen(data) + 1);

			g_jobmgr->param.mask = inet_addr(data);
			data += (strlen(data) + 1);

			g_jobmgr->param.gateway = inet_addr(data);
			data += (strlen(data) + 1);

			if(set_sys_time(data))
				return -1;

			if(config_py1(&g_jobmgr->param) < 0)
				return -1;
			//add_route(g_jobmgr->routes, ntohl(g_jobmgr->param.gapip), 32);
			break;
			
		case '2':
			len = strlen(data);
			if(g_jobmgr->routestr)
				SCFree(g_jobmgr->routestr);
			if(len == 0) 
			{
				g_jobmgr->routestr = NULL;
				clear_routes(g_jobmgr->routes);
				cmd_system_novty("vtysh -c 'write file'");
				break;
			}
			g_jobmgr->routestr = (char *)SCMalloc(len + 1);
			if(g_jobmgr->routestr == NULL)
			{
				SCLogError( "g_jobmgr->routestr alloc error!");
				return -1;
			}
                   memset(g_jobmgr->routestr, 0, len + 1);
			memcpy(g_jobmgr->routestr, data, len);
			g_jobmgr->routestr_len = len;
			//SCLogInfo("routestr: %s\n", g_jobmgr->routestr);
			add_routes(g_jobmgr->routes, data, len, card_intf[0]);
			cmd_system_novty("vtysh -c 'write file'");
			break;
			
		case '3': //firmware
		{
			static int fd = -1;
			static unsigned int file_len = 0;
			static unsigned int curr_len = 0;
			unsigned int slicelen;
			int name_len;
			char tag_3;

			tag_3 = *data;
			data += 2;
			if(tag_3 == '0')
			{
				len = strlen(data);
				space_to_zero(data, len);
				file_len = atoi(data);
				curr_len = 0;
				SCLogInfo("file_len: %d\n", file_len);
				name_len = len - strlen(data) - 1;
				data += (strlen(data) + 1);
				if(name_len >= FILE_NAME_LEN)
				{
					SCLogError( "file name is too long!");
					file_len = 0;
					curr_len = 0;
					return -1;
				}
				memset(upgrade_file_name, 0, sizeof(FILE_NAME_LEN));
				memcpy(upgrade_file_name, data, name_len);
				SCLogInfo("file: %s\n", upgrade_file_name);
				snprintf(cmd, sizeof(cmd), "/tmp/%s", upgrade_file_name);
				
				fd = open(cmd, O_WRONLY | O_CREAT|O_EXCL, 0600);
				if (-1 == fd)
				{
					if (EEXIST == errno)
						fd = open("/tmp/temp", O_WRONLY |O_TRUNC, 0600);
					if (-1 == fd)
					{
						file_len = 0;
						SCLogError( "open firmware_temp failed, %s\n", strerror(errno));
						return -1;
					}
				}
				
				break;
			}
			else if(tag_3 == '1')
			{
				slicelen = ntohl(*(unsigned int *)data);
				data += 4;
				curr_len += slicelen;
				//printf("curr_len: %d, slicelen: %d\n", curr_len, slicelen);

				if(!slicelen && !file_len)
					break;

				if(slicelen > 0 && write(fd, data, slicelen) < (int)slicelen)
				{
					file_len = 0;
					curr_len = 0;
					close(fd);
					SCLogError( "write %s failed, %s\n", upgrade_file_name, strerror(errno));
					cmd_system_novty_arg("/bin/rm -f /tmp/%s", upgrade_file_name);
					memset(upgrade_file_name, 0, sizeof(FILE_NAME_LEN));
					return -1;
				}
				
				if(slicelen == 0)
				{
					icmp_reply(buf, length);
					if(curr_len != file_len)
					{
						SCLogError( "load file %s failed\n", upgrade_file_name);
						cmd_system_novty_arg("/bin/rm -f /tmp/%s", upgrade_file_name);
						memset(upgrade_file_name, 0, sizeof(FILE_NAME_LEN));
					}
					else
					{
						SCLogInfo("load file %s success\n", upgrade_file_name);
						upgrade_fw(upgrade_file_name);
					}
					file_len = 0;
					curr_len = 0;
					close(fd);
					return 0;
				}
				else if(curr_len > file_len)
				{
					file_len = 0;
					curr_len = 0;
					close(fd);
					SCLogError( "load file %s failed\n", upgrade_file_name);
					cmd_system_novty_arg("/bin/rm -f /tmp/%s", upgrade_file_name);
					memset(upgrade_file_name, 0, sizeof(FILE_NAME_LEN));
				}
				
				//printf("this time ok\n");
			}
			break;
		}

		default:
			return -1;
	}
	
	icmp_reply(buf, length);
	return 0;

//send:

	send_len = sendto(g_eth0fd, buf, length, 0, (struct sockaddr *)&g_eth0_sl, sizeof(g_eth0_sl));
	if(send_len < 0)
	{
		SCLogError( "sendto error: %s\n", strerror(errno));
	}
	return -1;
}

void parse_tcp_state(unsigned char flags)
{	
	if(flags & 0x2) //syn
	{
		g_jobmgr->handshake_state = TCP_SYN;
		//printf("received ack\n");
	}
	/*else if(tcph->ack && tcph->syn)
	{
		if(g_jobmgr->handshake_state != TCP_SYN)
			g_jobmgr->handshake_state = TCP_IDLE;
		else
			g_jobmgr->handshake_state = TCP_ACK_SYN;
	}*/
	else if(flags & 0x10) //ack
	{
		if(g_jobmgr->handshake_state != TCP_SYN)
			g_jobmgr->handshake_state = TCP_IDLE;
		else
			g_jobmgr->handshake_state = TCP_ACK;

		g_jobmgr->conncnt++;
	}
	else if(flags & 0x1) //fin
	{
		g_jobmgr->conncnt--;
	}
}

int  build_cardid_ippacket(struct iphdr *iph, struct tcphdr *tcph, unsigned char *buf, int *iplen)
{
	struct iphdr *newiph = NULL;
	struct tcphdr *newtcph = NULL;
	unsigned char *data = NULL;
	unsigned int id = g_jobmgr->tcpkey.id;
	
	if(buf  == NULL || iplen == NULL)
		return -1;
	newiph = (struct iphdr *)buf;
	newtcph = (struct tcphdr *)(buf + sizeof(struct iphdr));
	data = (unsigned char *)(buf + sizeof(struct iphdr) + sizeof(struct tcphdr));
	
	newiph->version = 4;
	newiph->ihl = sizeof(struct iphdr) >> 2;
	newiph->tos = 0;
	newiph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(unsigned int);
	newiph->id = 0;
	newiph->frag_off = 0;
	newiph->ttl = 64;
	newiph->protocol = IPPROTO_TCP;
	newiph->check = 0;
	newiph->saddr = iph->saddr;
	newiph->daddr = iph->daddr;
	newiph->check = cal_cksum((unsigned short *)newiph, sizeof(struct iphdr));

	newtcph->source = tcph->source;
	newtcph->dest = tcph->dest;
	newtcph->seq = 0;
	newtcph->ack_seq = 0;
	newtcph->check = 0;
	newtcph->doff = 5;
	newtcph->window = 0;
	newtcph->check = 0;
	newtcph->urg_ptr = 0;
	memcpy(data, &id, 4);
	newtcph->check = tcp_cksum(newiph->saddr, newiph->daddr, (unsigned short *)newtcph, 
		                                                                  sizeof(struct tcphdr) + sizeof(unsigned int));

	*iplen = newiph->tot_len;
	return 0;
}

void send_cardid(struct iphdr *iph, struct tcphdr *tcph, unsigned char *buf)
{
	int send_len;
	int length = 0;
	unsigned char new_pkt[64] = {0};

	memcpy(new_pkt, buf, 14);
	build_cardid_ippacket(iph, tcph, new_pkt + 14, &length);
	send_len = sendto(g_eth0fd, new_pkt, length + 14, 0, (struct sockaddr *)&g_eth0_sl, sizeof(g_eth0_sl));
	if(send_len < 0)
	{
		SCLogError( "sendto error: %s, %d\n", strerror(errno), __LINE__);
	}
	/*printf("length: %d\n", length);
	for(int i = 0; i < (length + 14); i++)
	{
		printf("%02x ", new_pkt[i]);
		if((i+1) % 8 == 0)
			printf("\n");
	}
	printf("\n");*/

	g_jobmgr->handshake_state = TCP_IDLE;
}

void init_raw_socket()
{
	struct ifreq ifr;

	g_eth0fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(g_eth0fd == -1)
	{
		SCLogError( "create raw socket failed!\n");
		return;
	}
	/*memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, card_intf[0], sizeof(ifr.ifr_name));
	ioctl(g_eth0fd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(g_eth0fd, SIOCSIFFLAGS, &ifr);*/
	
	memset(&g_eth0_sl, 0x00, sizeof(g_eth0_sl));
	memset(&ifr, 0x00, sizeof(ifr));
	g_eth0_sl.sll_family = AF_PACKET;
	g_eth0_sl.sll_protocol = htons(ETH_P_ALL);
	strncpy(ifr.ifr_name, card_intf[0], sizeof(ifr.ifr_name));
	ioctl(g_eth0fd, SIOCGIFINDEX, &ifr);
	g_eth0_sl.sll_ifindex = ifr.ifr_ifindex;
	bind(g_eth0fd, (struct sockaddr *)&g_eth0_sl, sizeof(g_eth0_sl));

	
	g_eth1fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(g_eth1fd == -1)
	{
		SCLogError( "create raw socket failed!\n");
		return;
	}
	/*memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, card_intf[1], sizeof(ifr.ifr_name));
	ioctl(g_eth1fd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(g_eth1fd, SIOCSIFFLAGS, &ifr);*/

	memset(&g_eth1_sl, 0x00, sizeof(g_eth1_sl));
	memset(&ifr, 0x00, sizeof(ifr));
	g_eth1_sl.sll_family = AF_PACKET;
	g_eth1_sl.sll_protocol = htons(ETH_P_ALL);
	strncpy(ifr.ifr_name, card_intf[1], sizeof(ifr.ifr_name));
	ioctl(g_eth1fd, SIOCGIFINDEX, &ifr);
	g_eth1_sl.sll_ifindex = ifr.ifr_ifindex;
	bind(g_eth1fd, (struct sockaddr *)&g_eth1_sl, sizeof(g_eth1_sl));

}

void get_tcpkey(struct TcpPayloadKey*key, int num)
{
	RAND_bytes(key->key, num);
	RAND_bytes(key->iv, num);
	//memset(key->key, '1', 16);
	//memset(key->iv, '1', 16);
	print_dump(key->key, 16, "key");
	print_dump(key->iv, 16, "iv");
}

int send_tcpkey()
{
	int ret = 0, error;
	unsigned char buf[64] = {0};
	unsigned int *id;
	struct timeval tv = {SSL_HEARTBEAT_TIME_VAL, 0};

	if(g_jobmgr->session->connected)
	{
		g_jobmgr->tcpkey.id = 0;
		get_tcpkey(&g_jobmgr->tcpkey, 16);
		
		/*send tcpkey*/
		ret = SSL_write(g_jobmgr->session->ctx.ssl, &g_jobmgr->tcpkey, sizeof(struct TcpPayloadKey));
		error = SSL_get_error(g_jobmgr->session->ctx.ssl, ret);
		if(error != SSL_ERROR_NONE)
		{
			SCLogError( "SSL_write error\n");
			return -1;
		}

		/*receive key id*/
		error = SSL_read(g_jobmgr->session->ctx.ssl, buf, 64);
		if(error != sizeof(int))
		{
			SCLogError( "read key id error\n");
			return -1;
		}
		id = (unsigned int *)buf;
		g_jobmgr->tcpkey.id = *id;
		SCLogInfo("cardid: %08x\n", ntohl(g_jobmgr->tcpkey.id));

		event_add(g_jobmgr->ssl_hb_timer, &tv);
	}
	return 0;
}

void timer_ssl_hb(evutil_socket_t fd, short ev, void *args)
{
	int ret = 0, error;
	char buf[64] = {0};
	struct jobmgr *mgr = (struct jobmgr *)args;
	struct timeval tv = {SSL_HEARTBEAT_TIME_VAL, 0};
	
	strcpy(buf, "request");
	ret = SSL_write(mgr->session->ctx.ssl, buf, strlen(buf));
	error = SSL_get_error(mgr->session->ctx.ssl, ret);
	if(error != SSL_ERROR_NONE)
		goto err;
	
	ret = SSL_read(mgr->session->ctx.ssl, buf, 64);
	error = SSL_get_error(mgr->session->ctx.ssl, ret);
	if(error != SSL_ERROR_NONE)
		goto err;
	
	event_add(mgr->ssl_hb_timer, &tv);
	return;
err:
	SCLogInfo("ssl disconnect gap, ret = %d\n", ret);
	ssl_disconnect_gap();
	mgr->gap_active = FALSE;
}

void timer_free_ssl(evutil_socket_t fd, short ev, void *args)
{
	struct jobmgr *mgr = (struct jobmgr *)args;
	struct timeval tv = {SSL_SESSION_EXPIRE_TIME_VAL, 0};

	if(!mgr->gap_active)
	{
		SCLogInfo("ssl disconnect gap ...\n");
		ssl_disconnect_gap();
		return;
	}
	mgr->gap_active = FALSE;
	event_add(mgr->ssl_free_timer, &tv);
}

void timer_ssl_reconnect(evutil_socket_t fd, short ev, void *args)
{
	struct jobmgr *mgr = (struct jobmgr *)args;
	mgr->session->connect_failed_times = 0;
}

void timer_check_eth0(evutil_socket_t fd, short ev, void *args)
{
	static int eth0_running = 1;
	struct ifreq ifr0;

	strcpy(ifr0.ifr_name, "eth0");
	if(ioctl(g_eth0fd, SIOCGIFFLAGS, &ifr0) < 0)
		SCLogError( "ioctl failed, %s\n", strerror(errno));
	if(!(ifr0.ifr_flags & IFF_RUNNING) && eth0_running)
	{
		eth0_running = 0;
		if(system("ifconfig eth1 down") == -1)
			SCLogError( "system(\"ifconfig eth1 down\") failed!\n");
	}
	else if((ifr0.ifr_flags & IFF_RUNNING) && !eth0_running)
	{
		eth0_running = 1;
		if(system("ifconfig eth1 up") == -1)
			SCLogError( "system(\"ifconfig eth1 up\") failed!\n");
	}
}

void* jobmgr_loopthread(void *args)
{
	struct jobmgr *mgr = args;
	SCLogInfo("jobmgr running: %p", mgr);
	mgr->ready = 1;
	int ret = event_base_loop(mgr->base, 0);
	SCLogInfo("jobmgr finish: %p %d", mgr, ret);
	return NULL;
}

struct jobmgr * jobmgr_new()
{
	struct jobmgr *mgr = SCMalloc(sizeof(struct jobmgr));
	//struct timeval tv0 = { SSL_ACTIVE_CHECK_INTERVAL, 0 };
	struct timeval tv1 = { 1, 0 };
	//struct sched_param sched;
	//sched.sched_priority = -1;

	assert(mgr);
	memset(mgr, 0, sizeof(struct jobmgr));
	pthread_mutex_init(&mgr->ssl_mutex, NULL);

	mgr->eth0_buf = (unsigned char *)SCMalloc(RCV_BUF_SIZE);
	mgr->eth1_buf = (unsigned char *)SCMalloc(RCV_BUF_SIZE);
	assert(mgr->eth0_buf && mgr->eth1_buf);
	
	mgr->param.gapip = inet_addr("1.2.3.4");
	
	mgr->base =  event_base_new();
	mgr->ssl_free_timer = event_new(mgr->base, -1, 0, timer_free_ssl, mgr);
	mgr->ssl_hb_timer = event_new(mgr->base, -1, 0, timer_ssl_hb, mgr);
	mgr->ssl_reconnect_timer = event_new(mgr->base, -1, 0, timer_ssl_reconnect, mgr);
	
	//mgr->ssl_check_timer =  event_new(mgr->base, -1, EV_READ|EV_PERSIST, timer_check_ssl, mgr);
	//event_add(mgr->ssl_check_timer, &tv0);
	
	mgr->eth0timer =  event_new(mgr->base, -1, EV_READ|EV_PERSIST, timer_check_eth0, mgr);
	event_add(mgr->eth0timer, &tv1);

	pthread_create(&mgr->evthread, NULL, jobmgr_loopthread, mgr);
	//pthread_setschedparam(mgr->evthread, SCHED_RR, &sched);
	
#ifdef USER_MEM_ALLOC
    ThreadMemInit("", mgr->evthread);
#endif
	while (mgr->ready == 0)
		usleep(1000);
		
	return mgr;
}

int ssl_connect_gap()
{
	int ret;
	struct timeval tv = {SSL_SESSION_EXPIRE_TIME_VAL, 0};

	if(g_jobmgr->session->connect_failed_times >= SSL_CONNECT_MAX_ERR_TIMES)
	{
		tv.tv_sec = SSL_RECONNECT_TIME_VAL;
		if(!evtimer_pending(g_jobmgr->ssl_reconnect_timer, NULL))
		{
			event_add(g_jobmgr->ssl_reconnect_timer, &tv);
		}
		return 0;
	}
	SCLogInfo("ssl_connect_gap() ..., connect_failed_times: %d\n", g_jobmgr->session->connect_failed_times);

	pthread_mutex_lock(&g_jobmgr->ssl_mutex);
	if(!g_jobmgr->session->connected)
	{
		g_jobmgr->session->connected = 1;
	}
	else
	{
		pthread_mutex_unlock(&g_jobmgr->ssl_mutex);
        SCLogInfo(">>>>>>>>>>>>>>>>>>>>>>>>>>>_________<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
		return 0;
	}
	pthread_mutex_unlock(&g_jobmgr->ssl_mutex);
	
	g_jobmgr->session->gap_addr.sin_family = AF_INET;
	g_jobmgr->session->gap_addr.sin_port = htons(SSL_DEFAULT_PORT);
	g_jobmgr->session->gap_addr.sin_addr.s_addr = g_jobmgr->param.gapip;
	SCLogInfo("gapip: %s\n", inet_ntoa(g_jobmgr->session->gap_addr.sin_addr));
	if(init_ssl_client_session(g_jobmgr->session) < 0)
	{
		SCLogInfo("ssl connect fail\n");
		g_jobmgr->session->connect_failed_times++;
		g_jobmgr->session->connected = 0;
		return -1;
	}
    g_jobmgr->session->connect_failed_times = 0;
	
	ret = send_tcpkey();
	if(ret < 0)
	{
		free_ssl_session(g_jobmgr->session);
	}
	else
		event_add(g_jobmgr->ssl_free_timer, &tv);
	
	return ret;
}

void ssl_disconnect_gap()
{
	event_del(g_jobmgr->ssl_free_timer);
	event_del(g_jobmgr->ssl_hb_timer);
	free_ssl_session(g_jobmgr->session);
}

void recv_from_win(evutil_socket_t fd, short ev, void *args)
{
	struct jobmgr *mgr = (struct jobmgr *)args;
	struct ethhdr *ethh = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	int iphl;
	int rcv_len, send_len, pkt_len;
	unsigned char *buf = mgr->eth1_buf;
	struct route_node * route = NULL;

	rcv_len = recvfrom(fd, buf, RCV_BUF_SIZE, 0, NULL, NULL);
	if(rcv_len < 0)
		return;

	ethh = (struct ethhdr *)buf;

	if(htons(ETH_P_IP) == ethh->h_proto)
	{
		iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
		pkt_len = sizeof(struct ethhdr) + ntohs(iph->tot_len);
		if(rcv_len > 60 && rcv_len > pkt_len)
		{
			SCLogInfo("rcv_len: %d, pkt_len: %d\n", rcv_len, pkt_len);
		}

		if(IPPROTO_ICMP == iph->protocol)
		{
			if(icmp_parse(buf, pkt_len) <= 0)
			{
				if(mgr->session->gap_addr.sin_addr.s_addr != mgr->param.gapip)
				{
					if(mgr->session->connected)
					{
						SCLogInfo("ssl disconnect gap ...\n");
						ssl_disconnect_gap();
					}
				}

                g_jobmgr->session->connect_failed_times = 0;
				event_del(g_jobmgr->ssl_reconnect_timer);
				return;
			}
		}

		route = find_route(mgr->routes, ntohl(iph->daddr));
		
		if((iph->daddr ==  mgr->param.gapip) || route)
		{
			mgr->sendpkts++;

			if(iph->protocol == IPPROTO_TCP)
			{
				unsigned short tot_len;
				iphl = iph->ihl*4;
				tcph = (struct tcphdr *)(buf + ETH_HEAD_LEN+ iphl);

				if(!mgr->session->connected)
				{
					if(ssl_connect_gap() < 0)
						return;
				}

				if(mgr->session->connected)
				{
					mgr->gap_active = TRUE;
				}

				if(iph->saddr ==  mgr->param.gapip)
				{
					SCLogInfo("eth1 rcv saddr==gapip");
					return;
				}

				if(tcph->dest == htons(SSL_DEFAULT_PORT)
				    || tcph->source == htons(SSL_DEFAULT_PORT))
					return;
				
				parse_tcp_state(buf[ETH_HEAD_LEN + iphl + 13]);
                if(mgr->session->connected)
                {
    				if((buf[ETH_HEAD_LEN + iphl + 13] == TCP_FLAGS_SYN)
    					|| (buf[ETH_HEAD_LEN + iphl + 13] == TCP_FLAGS_SYN_ACK))
    				{
    					//SCLogInfo("flags: 0x%02x", buf[14 + iphl + 13]);
    					tot_len = ntohs(iph->tot_len) + 4;
    					iph->tot_len = htons(tot_len);
    					iph->check = 0;
    					iph->check = cal_cksum((unsigned short *)iph, iphl);

    					memcpy((unsigned char *)tcph + tcph->doff*4, &mgr->tcpkey.id, 4);
    					tcph->check = 0;
    					tcph->check = tcp_cksum(iph->saddr, iph->daddr, (unsigned short *)tcph, tcph->doff*4 + 4);
    					
    					pkt_len += 4;
    				}
    				else
    				{
    				    //if(mgr->session->connected)
    				    {
        					encrypt_tcppayload(iph, tcph, ntohs(iph->tot_len) - iph->ihl*4, mgr->tcpkey.key, 
        									KEY_LEN, mgr->tcpkey.iv);
                        }
    				}
                }
			}
		}
		
	}
	else if(htons(ETH_P_ARP) == ethh->h_proto)
	{
		if(rcv_len > 60)
			SCLogInfo("rcv_len: %d\n", rcv_len);
		pkt_len = rcv_len;
	}
	else if(htons(ETH_P_IPV6) == ethh->h_proto)
	{
		int payload_len = (buf[18]<<8) | buf[19];
		pkt_len = payload_len + ETH_HEAD_LEN + IPV6_HEAD_LEN;
		if(rcv_len != pkt_len)
		{
			SCLogInfo("rcv_len: %d, pkt_len: %d\n", rcv_len, pkt_len);
		}
		pkt_len = rcv_len;
	}
	else
	{
		//SCLogInfo("ethh->h_proto: %04x, rcv_len: %d\n", ntohs(ethh->h_proto), rcv_len);
		pkt_len = rcv_len;
	}

	send_len = sendto(g_eth0fd, buf, pkt_len, 0, (struct sockaddr *)&g_eth0_sl, sizeof(g_eth0_sl));
	if(send_len < 0)
	{
		//SCLogError( "sendto error: %s\n", strerror(errno));
	}
}

void recv_from_wire(evutil_socket_t fd, short ev, void *args)
{
	struct jobmgr *mgr = (struct jobmgr *)args;
	struct ethhdr *ethh = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	int rcv_len, send_len, pkt_len;
	unsigned char *buf = mgr->eth0_buf;

	rcv_len = recvfrom(fd, buf, RCV_BUF_SIZE, 0, NULL, NULL);
	if(rcv_len < 0)
		return;

	ethh = (struct ethhdr *)buf;

	if(htons(ETH_P_IP) == ethh->h_proto) 
	{
		struct route_node *route = NULL;
		iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
		route = find_route(mgr->routes, ntohl(iph->saddr));

		pkt_len = sizeof(struct ethhdr) + ntohs(iph->tot_len);
		if(rcv_len > 60 && rcv_len > pkt_len)
		{
			SCLogInfo("rcv_len: %d, pkt_len: %d\n", rcv_len, pkt_len);
			//print_dump(buf, rcv_len, NULL);
		}

		if((iph->saddr ==  mgr->param.gapip) || route)
		{
			mgr->rcvpkts++;
			
			if(iph->protocol == IPPROTO_TCP)
			{
				tcph = (struct tcphdr *)(buf + ETH_HEAD_LEN + iph->ihl*4);

				if(!mgr->session->connected)
				{
					if(ssl_connect_gap() < 0)
                        return;
				}

				if(mgr->session->connected
					&& (tcph->source != htons(SSL_DEFAULT_PORT))
                    && (tcph->dest != htons(SSL_DEFAULT_PORT)))
				{
                	mgr->gap_active = TRUE;
				}
				
				if(tcph->dest == htons(22) 
				    || tcph->dest == htons(SSL_DEFAULT_PORT)
				    || tcph->source == htons(SSL_DEFAULT_PORT))
					return;
			}

			if(tcph)
			{
			    if(mgr->session->connected)
			    {
    				decrypt_tcppayload(iph, tcph, ntohs(iph->tot_len) - iph->ihl*4, mgr->tcpkey.key, 
    									KEY_LEN, mgr->tcpkey.iv);
			    }
			}
		}
	}
	else if(htons(ETH_P_ARP) == ethh->h_proto)
	{
		if(rcv_len > 60)
			SCLogInfo("rcv_len: %d\n", rcv_len);
		pkt_len = rcv_len;
	}
	else if(htons(ETH_P_IPV6) == ethh->h_proto)
	{
		int payload_len = (buf[18]<<8) | buf[19];
		pkt_len = payload_len + ETH_HEAD_LEN + IPV6_HEAD_LEN;
		if(rcv_len != pkt_len)
		{
			SCLogInfo("rcv_len: %d, pkt_len: %d\n", rcv_len, pkt_len);
		}
		pkt_len = rcv_len;
	}
	else
	{
		//SCLogInfo("ethh->h_proto: %04x, rcv_len: %d\n", ntohs(ethh->h_proto), rcv_len);
		pkt_len = rcv_len;
	}

	send_len = sendto(g_eth1fd, buf, pkt_len, 0, (struct sockaddr *)&g_eth1_sl, sizeof(g_eth1_sl));
	if(send_len < 0)
	{
		//SCLogError( "sendto error: %s\n", strerror(errno));
	}
}

#if USE_THREAD_RCV_PKT
void *thread_recvfrom_win(void *args)
{
	struct jobmgr *mgr = (struct jobmgr *)args;
	
	SCLogInfo("thread ruuning\n");
	while(1)
	{
		recv_from_win(g_eth1fd, 0, mgr);
	}
}

void * thread_recvfrom_wire(void *args)
{
	struct jobmgr *mgr = (struct jobmgr *)args;

	SCLogInfo("thread ruuning\n");
	while(1)
	{
		recv_from_wire(g_eth0fd, 0, mgr);
	}
}
#endif

void start_work()
{
#if USE_THREAD_RCV_PKT
	pthread_create(&g_jobmgr->ph2thread, NULL, thread_recvfrom_win, g_jobmgr);
#ifdef USER_MEM_ALLOC
    ThreadMemInit("", g_jobmgr->ph2thread);
#endif

	pthread_create(&g_jobmgr->ph1thread, NULL, thread_recvfrom_wire, g_jobmgr);  
#ifdef USER_MEM_ALLOC
    ThreadMemInit("", g_jobmgr->ph1thread);
#endif

#else
	g_jobmgr->ev_rcv_win = event_new(g_jobmgr->base, g_eth1fd, 
					EV_READ|EV_PERSIST, recv_from_win, g_jobmgr);
	event_add(g_jobmgr->ev_rcv_win, NULL);
	
	g_jobmgr->ev_rcv_wire = event_new(g_jobmgr->base, g_eth0fd, 
					EV_READ|EV_PERSIST, recv_from_wire, g_jobmgr);
	event_add(g_jobmgr->ev_rcv_wire, NULL);
#endif
}

void setif_promisc()
{
	char cmd[32] = {0};
	struct ifreq ifr0, ifr1;
	int sock;

	sock = socket(AF_INET,SOCK_DGRAM,0);
	
	memset(&ifr0, 0, sizeof(ifr0));
	strcpy(ifr0.ifr_name, card_intf[0]);
	ioctl(sock, SIOCGIFFLAGS, &ifr0);

	memset(&ifr1, 0, sizeof(ifr1));
	strcpy(ifr1.ifr_name, card_intf[1]);
	ioctl(sock, SIOCGIFFLAGS, &ifr0);

	if(!(ifr0.ifr_flags & IFF_RUNNING) || !(ifr1.ifr_flags & IFF_RUNNING)) {
		if(system("/etc/init.d/networking restart") == -1)
				SCLogError( "/etc/init.d/networking start failed!\n");
	}
	close(sock);
	
	snprintf(cmd, sizeof(cmd), "ifconfig %s promisc", card_intf[0]);
	if(system(cmd) == -1)
		return;

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "ifconfig %s promisc", card_intf[1]);
	if(system(cmd) == -1)
		return;
}

void set_process_priority()
{
	struct sched_param param = {};
	int maxRR = sched_get_priority_max(SCHED_RR);

	if(maxRR == -1)
	{
		SCLogError( "sched_get_priority_max() failed!\n");
		return;
	}
	
	SCLogInfo("maxRR: %d\n", maxRR);
	
	param.sched_priority = (maxRR*2)/3;
	
	if(sched_setscheduler(getpid(), SCHED_RR, &param) == -1)
	{
		SCLogError( "sched_setscheduler() failed!\n");
	}
	SCLogInfo("Policy: %d\n", sched_getscheduler(0));
}


static void usage()
{
    printf("gap20 -Do:i:\n");
    printf("option:\n");
    printf("\tD run as daemon.\n");
    printf("\ti <interface> Inner interface \n");
    printf("\to <interface> Outer interface \n");
}

int main(int argc, char **argv)
{	
	int ch;
	int daemon_mode = 0;
	char *config_file = "/etc/gap20.conf";
	struct thread temp;    

	
	while((ch = getopt(argc, argv, "Df:i:o:"))!= -1)
	{
		switch(ch)
		{
		case 'D':
			daemon_mode = 1;
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'i':
			memset(card_intf[0], 0, 32);
			strcpy(card_intf[0], optarg);
			break;
		case 'o':
			memset(card_intf[1], 0, 32);
			strcpy(card_intf[1], optarg);
			break;
		default:
			usage();
			return -1;
		}
	}
	if(daemon_mode)
		daemon(0, 0);
	
#ifdef USER_MEM_ALLOC
    ThreadMemInit("", pthread_self());
#endif
	SCLogLoadConfig(0, "gap.log");

	set_process_priority();

	setif_promisc();

	init_raw_socket();
	assert(g_eth0fd != -1 && g_eth1fd != -1);
	
	g_jobmgr = jobmgr_new();

	g_jobmgr->session = alloc_ssl_session();

	init_ssl_lib();
	init_ssl_cfg_as_default(&g_jobmgr->ssl_cfg);

	master = thread_master_create();

    signal_init(master, 0, NULL);

	cmd_init(1);

	vty_init(master);

	card_cmd_init();
	
	/* Get configuration file. */
	vty_read_config(config_file, config_default);
	
	/* Make vty server socket. */
	vty_serv_sock(vty_addr, vty_port, APP_VTYSH_PATH);

	start_work();

	while( thread_fetch(master, &temp))
		thread_call(&temp );

	return 0;
}
