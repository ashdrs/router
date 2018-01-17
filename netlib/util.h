
#ifndef	UTIL_H
#define	UTIL_H

#include <arpa/inet.h>
#include <netinet/ip.h>

char *MacToString(u_char *d);
char *InetToString(struct in_addr *addr);
char *InaddrToString(in_addr_t addr);

u_int16_t checksum(unsigned char *data, int len);
u_int16_t checksum2(unsigned char *data1, int len1, unsigned char *data2, int len2);
int checkIPchecksum(struct ip *iphdr, unsigned char *option, int optionLen);

int SendArpRequest(int socket, in_addr_t target_ip, unsigned char target_hwaddr[6], in_addr_t my_ip, unsigned char my_hwaddr[6]);

#endif	//UTIL_H