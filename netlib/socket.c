#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>

#ifndef __linux
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#else
#include	<sys/socket.h>
#include	<netinet/if_ether.h>
#include	<netpacket/packet.h>
#endif

#include <net/if.h>
#include <fcntl.h>
#include <ifaddrs.h>

#include <netinet/in.h>

#include "log.h"
#include "socket.h"


int InitRawSocket(char *device, int promiscFlag, int ipOnly){
	int soc;

#ifndef __linux
	if((soc = OpenBpf(device)) < 0){
		ErrorLog("open_bpf");exit(EXIT_FAILURE);
	}
#else
	struct ifreq	ifreq;
	struct sockaddr_ll	sa;

	if(ipOnly){
		if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP))) < 0){
			ErrorLog("open_socket");exit(EXIT_FAILURE);
		}
	}else{
		if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0){
			ErrorLog("open_socket");exit(EXIT_FAILURE);
		}
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name)-1);
	if(ioctl(soc, SIOCGIFINDEX, &ifreq) < 0){
		ErrorLog("ioctl");
		close(soc);
		exit(EXIT_FAILURE);
	}
	sa.sll_family = PF_PACKET;
	if(ipOnly){
		sa.sll_protocol = htons(ETH_P_IP);
	}else{
		sa.sll_protocol = htons(ETH_P_ALL);
	}
	sa.sll_ifindex = ifreq.ifr_ifindex;
	if(bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0){
		ErrorLog("bind");
		close(soc);
		exit(EXIT_FAILURE);
	}

	if(promiscFlag){
		if(ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0){
			ErrorLog("ioctl");
			close(soc);
			exit(EXIT_FAILURE);
		}
		ifreq.ifr_flags = ifreq.ifr_flags|IFF_PROMISC;
		if(ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0){
			ErrorLog("ioctl");
			close(soc);
			exit(EXIT_FAILURE);
		}
	}
#endif
	return soc;
}

int GetDeviceInfo(char *device, u_char hwaddr[6], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask){
#ifndef __linux
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa, *sa2;
	struct sockaddr_dl *dl;
	u_char *macaddr;
	
	getifaddrs(&ifap);
	for(ifa=ifap; ifa; ifa=ifa->ifa_next){
		if(strcmp(ifa->ifa_name,device)==0){
			dl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (dl->sdl_family == AF_LINK && dl->sdl_type == IFT_ETHER) {
				macaddr = (unsigned char *)LLADDR(dl);
				memcpy(hwaddr, macaddr, 6);
			}else if(ifa->ifa_addr->sa_family == AF_INET){
				sa = (struct sockaddr_in *) ifa->ifa_addr;
				*uaddr=sa->sin_addr;

				sa2 = (struct sockaddr_in *) ifa->ifa_netmask;
				*mask=sa2->sin_addr;

				subnet->s_addr=((uaddr->s_addr)&(mask->s_addr));
			}
		}
	}
	freeifaddrs(ifap);

#else

	struct ifreq ifreq;
	struct sockaddr_in addr;
	int soc;
	u_char *p;

	if ((soc=socket(PF_INET, SOCK_DGRAM,0)) < 0) {
		ErrorLog("socket");
		return -1;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name)-1);

	if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1) {
		ErrorLog("ioctl SIOCGIFHWADDR");
		close(soc);
		return -1;
	}else{
		p = (u_char *)&ifreq.ifr_hwaddr.sa_data;
		memcpy(hwaddr, p, 6);
	}

	if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1) {
		ErrorLog("ioctl SIOCGIFADDR");
		close(soc);
		return -1;
	}else if (ifreq.ifr_addr.sa_family != PF_INET) {
		ErrorLog("ioctl not PF_INET");
		close(soc);
		return -1;
	}else{
		memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
		*uaddr = addr.sin_addr;
	}

	if (ioctl(soc, SIOCGIFNETMASK, &ifreq) == -1) {
		ErrorLog("ioctl SIOCGIFNETMASK");
		close(soc);
		return -1;
	}else{
		memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
		*mask = addr.sin_addr;
	}

	subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));
	close(soc);

#endif

	return 0;
}

#ifndef __linux
int OpenBpf(char *ifname){
	char devfile[16];
	int soc = 0;
	int bufsize;
	struct ifreq ifr;

	//BPFデバイスファイルオープン
	int i;
	for(i=0; i<=5; i++){
		sprintf(devfile,"/dev/bpf%d",i);
		if((soc = open(devfile, O_RDWR, 0)) >= 0){
			break;
		}
	}
	if(soc < 0){
		InfoLog("cannot OpenBpf: %s=%s", ifname, devfile);
		return -1;
	}
	InfoLog("open: %s=%s,socket=%d", ifname, devfile, soc);

	//BPF内部のバッファサイズの設定
	bufsize = 8192;
	if(ioctl(soc, BIOCSBLEN, &bufsize) < 0){
		ErrorLog("ioctl BIOCSBLEN");
		return -1;
	}

	//インタフェース名の設定
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if(ioctl(soc, BIOCSETIF, &ifr) < 0){
		ErrorLog("ioctl BIOCSETIF");
		return -1;
	}
	InfoLog("bpf read from %s(%s)", ifr.ifr_name, devfile);

	//プロミスキャスモード
	if(ioctl(soc, BIOCPROMISC, NULL) < 0){
		ErrorLog("ioctl BIOCPROMISC");
		return -1;
	}

	//即時モード
	i = 1;
	if(ioctl(soc, BIOCIMMEDIATE, &i) < 0){
		ErrorLog("ioctl(BIOCIMMEDIATE)");
		return -1;
	}
	
//	ioctl(soc, BIOCFLUSH, NULL);       /* 受信バッファをフラッシュする */
	ioctl(soc, BIOCSHDRCMPLT, &i);	//MACアドレスを補間しない

	int z = 0;
	ioctl(soc, BIOCSSEESENT, &z); //これを0にしないと、writeしたものもBPFで取得するのでブリッジがバグる
//	ioctl(soc, BIOCSDIRECTION, BPF_D_IN);

//	ioctl(soc, BIOCFEEDBACK, BPF_D_INOUT);


	return soc;
}

#else

int DisableIpForward(){
	FILE *fp;
	if((fp=fopen("/proc/sys/net/ipv4/ip_forward","w"))==NULL){
		ErrorLog("cannot write /proc/sys/net/ipv4/ip_forward\n");
		return(-1);
	}
	fputs("0",fp);
	fclose(fp);
	return(0);
}

#endif