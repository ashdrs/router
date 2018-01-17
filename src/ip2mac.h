#ifndef IP2MAC_H
#define IP2MAC_H

#include "main.h"

IP2MAC *Ip2MacSearch(int deviceNo, in_addr_t addr, u_char *hwaddr);
IP2MAC *Ip2Mac(int deviceNo, in_addr_t addr, u_char *hwaddr);

int BufferSend();

#endif