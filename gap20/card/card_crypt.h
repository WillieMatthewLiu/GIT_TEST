#ifndef _CARD_CRYPT_H_
#define _CARD_CRYPT_H_

#include <openssl/aes.h>
#include <openssl/rc4.h>

#define KEY_LEN 16

struct TcpPayloadKey {
	unsigned int id;
	unsigned char iv[KEY_LEN];
	unsigned char key[KEY_LEN];
};

typedef struct _pseudo_header
{
	unsigned int sourceIP;
	unsigned int destIP;
	//unsigned char mbz; //must be zero
	unsigned short protocol;
	unsigned short tcp_length;
} PSEUDO_HEADER;


static inline unsigned short cal_cksum(unsigned short *addr, unsigned short len)  
{  
    register int nleft = len;  
    register unsigned short *w = addr;  
    register unsigned int sum = 0;  
    unsigned short answer = 0;
  
     /* Our algorithm is simple, using a 32 bit accumulator (sum), we add 
      * sequential 16 bit words to it, and at the end, fold back all the 
      * carry bits from the top 16 bits into the lower 16 bits. */  

     while (nleft > 1)  {  
         sum += *w++;  
         nleft -= 2;  
     }  
  
     /* mop up an odd byte, if necessary */  
     if (nleft == 1) {  
         *(unsigned char *)(&answer) = *(unsigned char *) w;  
         sum += answer;  
     }  
  
     /* add back carry outs from top 16 bits to low 16 bits */  
     sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16  将高16bit与低16bit相加 */  
     sum += (sum >> 16);                /* add carry 将进位到高位的16bit与低16bit 再相加*/  
     answer = ~sum;                     /* truncate to 16 bits */  
     return(answer);  
}  

static inline unsigned short tcp_cksum(unsigned int saddr, unsigned int daddr, unsigned short *addr, unsigned short len)  
{  
    register int nleft = len;  
    register unsigned short *w = NULL; 
    register unsigned int sum = 0;  
    unsigned short answer = 0;
    PSEUDO_HEADER psd;
    unsigned int i;

    saddr = ntohl(saddr);
    daddr = ntohl(daddr);

    psd.sourceIP = saddr;
    psd.destIP = daddr;
    //psd.mbz = 0;
    psd.protocol = 0x06;
    psd.tcp_length = len;
   
    w = (unsigned short *)&psd;
    for(i = 0; i < sizeof(PSEUDO_HEADER); i += 2)
        sum += *w++;

    w = addr;
     while (nleft > 1)  {  
         sum += htons(*w);  
         w++;
         nleft -= 2;  
     }  
  
     if (nleft == 1) {  
         *(unsigned char *)(&answer) = *(unsigned char *) w;  
         sum += htons(answer);  
     }  
  
     sum = (sum >> 16) + (sum & 0xffff);
     sum += (sum >> 16);               
     answer = ~sum;                   
     return(htons(answer));  
}

/*static inline unsigned short tcp_cksum(unsigned int saddr, unsigned int daddr, unsigned short *addr, unsigned short len)  
{  
    register int nleft = len;  
    register unsigned short *w = NULL; 
    register unsigned int sum = 0;  
    unsigned short answer = 0;
    PSEUDO_HEADER psd;
    unsigned int i;

printf("tcp_cksum: \n");
printf("saddr: %08x\n", saddr);
printf("daddr: %08x\n", daddr);
unsigned char *data = (unsigned char *)addr;
for(i = 0; i < len; i++)
{
	printf("%02x ", data[i]);
	if((i + 1) % 16 == 0)
		printf("\n");
}
printf("\n");
    psd.sourceIP = saddr;
    psd.destIP = daddr;
    //psd.mbz = 0;
    psd.protocol = 0x06;
    psd.tcp_length = len;
    w = (unsigned short *)&psd;
    for(i = 0; i < sizeof(PSEUDO_HEADER); i += 2) {
        sum += *w;
	 printf("%04x ", *w);
	 w++;
    }

    w = addr;
     while (nleft > 1)  {  
          sum += htons(*w);  
	  printf("%04x ", *w);
	  w++;
         nleft -= 2;  
     }  
  
     if (nleft == 1) {  
         *(unsigned char *)(&answer) = *(unsigned char *) w;  
         sum += htons(answer);  
	  printf("\n%04x\n", answer);
     }  
printf("\n");
  
     sum = (sum >> 16) + (sum & 0xffff);
     sum += (sum >> 16);               
     answer = ~sum;                   
     return(answer);  
}*/

void crypt_aesecb128_rc4(unsigned char *data, unsigned char *out, unsigned int datalen, unsigned char *userKey, 
                                                                                   int keylen, const int enc);
void crypt_aescbc128_rc4(unsigned char *data, unsigned char *out, unsigned int datalen, unsigned char *userKey, 
                                                                                   int keylen, unsigned char *userIv, const int enc);
void crypt_rc4(unsigned char *data, unsigned char *out, unsigned int datalen, unsigned char *userKey, 
                                                                                   int keylen);

void encrypt_tcppayload(struct iphdr *iph, struct tcphdr *tcph, int totlen, 
	                                                                  unsigned char *userKey, int keylen, unsigned char *userIv);
void decrypt_tcppayload(struct iphdr *iph, struct tcphdr *tcph, int totlen, 
	                                                                  unsigned char *userKey, int keylen, unsigned char *userIv);

#endif
