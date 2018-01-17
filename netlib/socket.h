
#ifndef	SOCKET_H
#define	SOCKET_H

#include <arpa/inet.h>

int OpenBpf(char *ifname);
int InitRawSocket(char *device, int promiscFlag, int ipOnly);
int GetDeviceInfo(char *device, u_char hwaddr[6], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask);
int DisableIpForward();

#endif	//SOCKET_H