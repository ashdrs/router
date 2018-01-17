#include <stdio.h>
#include <string.h>
#include <unistd.h>


#include "util.h"
#include <sys/socket.h>
#include <netinet/if_ether.h>

#include "log.h"

typedef struct {
	struct ether_header eth;
	struct ether_arp arp;
}PACKET_ARP;


char *MacToString(u_char *d){
	static char str[50];
//	char str[50];
	snprintf(str, 50, "%02x:%02x:%02x:%02x:%02x:%02x",
				d[0],d[1],d[2],d[3],d[4],d[5]);
	return str;
}

char *InetToString(struct in_addr *addr){
	static char str[50];
	inet_ntop(PF_INET, addr, str, sizeof(str));
	return str;
}

char *InaddrToString(in_addr_t addr){
	struct in_addr inaddr;

	inaddr.s_addr=addr;
	return InetToString(&inaddr);
}

u_int16_t checksum(u_char *data, int len){
	register u_int32_t sum;
	register u_int16_t *ptr;
	register int c;

	sum=0;
	ptr=(u_int16_t *)data;

	for(c=len;c>1;c-=2){
		sum+=(*ptr);
		if(sum&0x80000000){
			sum=(sum&0xFFFF)+(sum>>16);
		}
		ptr++;
	}
	if(c==1){
		u_int16_t val;
		val=0;
		memcpy(&val, ptr, sizeof(u_int8_t));
		sum+=val;
	}
	while(sum>>16){
		sum=(sum&0xFFFF)+(sum>>16);
	}
	return ~sum;
}

u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2){
	register u_int32_t sum;
	register u_int16_t *ptr;
	register int c;

	sum=0;
	ptr=(u_int16_t *)data1;
	for(c=len1;c>1;c-=2){
		sum+=(*ptr);
		if(sum&0x80000000){
			sum=(sum&0xFFFF)+(sum>>16);
		}
		ptr++;
	}
	if(c==1){
		u_int16_t val;
		val=((*ptr)<<8)+(*data2);
		sum+=val;
		if(sum&0x80000000){
			sum=(sum&0xFFFF)+(sum>>16);
		}
		ptr=(u_int16_t *)(data2+1);
		len2--;
	}else{
		ptr=(u_int16_t *)data2;
	}
	for(c=len2;c>1;c-=2){
		sum+=(*ptr);
		if(sum&0x80000000){
			sum=(sum&0xFFFF)+(sum>>16);
		}
		ptr++;
	}
	if(c==1){
		u_int16_t val;
		val=0;
		memcpy(&val, ptr, sizeof(u_int8_t));
		sum+=val;
	}

	while(sum>>16){
		sum=(sum&0xFFFF)+(sum>>16);
	}

	return ~sum;
}


int checkIPchecksum(struct ip *iphdr, u_char *option, int optionLen){
	struct ip iptmp;
	unsigned short sum;

	memcpy(&iptmp, iphdr, sizeof(struct ip));

	if(optionLen==0){
		sum=checksum((u_char *)&iptmp, sizeof(struct ip));
		if(sum==0||sum==0xFFFF){
			return 1;
		}else{
			return 0;
		}
	}else{
		sum=checksum2((u_char *)&iptmp, sizeof(struct ip), option, optionLen);
		if(sum==0||sum==0xFFFF){
			return 1;
		}else{
			return 0;
		}
	}
}

int SendArpRequest(int socket, in_addr_t target_ip, unsigned char target_hwaddr[6], in_addr_t my_ip, unsigned char my_hwaddr[6]){
	PACKET_ARP arp;
	int total;
	u_char *p;
	u_char buf[sizeof(struct ether_header)+sizeof(struct ether_arp)];
	union {
		unsigned long l;
		u_char c[4];
	}lc;
	int i;

	arp.arp.arp_hrd=htons(ARPHRD_ETHER);	//ハードウェアアドレスの種類（ARPHRD_ETHERは1）
	arp.arp.arp_pro=htons(ETHERTYPE_IP);	//プロトコルアドレスの種類（ETHERTYPE_IPは0x0800）
	arp.arp.arp_hln=6;						//ハードウェアアドレスの長さ（macアドレスは6）
	arp.arp.arp_pln=4;						//プロトコルアドレスの長さ（ipアドレスは4）
	arp.arp.arp_op=htons(ARPOP_REQUEST);	//オペレーション

	for(i=0;i<6;i++){
		arp.arp.arp_sha[i]=my_hwaddr[i];		//送信元macアドレス
	}
	for(i=0;i<6;i++){
		arp.arp.arp_tha[i]=0;				//送信先macアドレス
	}

	lc.l=my_ip;
	for(i=0;i<4;i++){
		arp.arp.arp_spa[i]=lc.c[i];			//送信元IPアドレス（プロトコルアドレス）
	}

	lc.l=target_ip;
	for(i=0;i<4;i++){
		arp.arp.arp_tpa[i]=lc.c[i];			//送信先IPアドレス（プロトコルアドレス）検索したいIP
	}

	//送信先macアドレス
	arp.eth.ether_dhost[0]=target_hwaddr[0];
	arp.eth.ether_dhost[1]=target_hwaddr[1];
	arp.eth.ether_dhost[2]=target_hwaddr[2];
	arp.eth.ether_dhost[3]=target_hwaddr[3];
	arp.eth.ether_dhost[4]=target_hwaddr[4];
	arp.eth.ether_dhost[5]=target_hwaddr[5];
	//送信元macアドレス
	arp.eth.ether_shost[0]=my_hwaddr[0];
	arp.eth.ether_shost[1]=my_hwaddr[1];
	arp.eth.ether_shost[2]=my_hwaddr[2];
	arp.eth.ether_shost[3]=my_hwaddr[3];
	arp.eth.ether_shost[4]=my_hwaddr[4];
	arp.eth.ether_shost[5]=my_hwaddr[5];

	arp.eth.ether_type=htons(ETHERTYPE_ARP); //種類

	memset(buf, 0, sizeof(buf));
	p=buf;
	memcpy(p, &arp.eth, sizeof(struct ether_header));
	p+=sizeof(struct ether_header);
	memcpy(p, &arp.arp, sizeof(struct ether_arp));
	p+=sizeof(struct ether_arp);
	total=p-buf;

	write(socket, buf, total);
	InfoLog("[info]SendArpRequest(%s)", InaddrToString(target_ip));
	return 0;
}

