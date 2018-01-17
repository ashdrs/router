#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <poll.h>

#ifndef __linux
#include <net/bpf.h>
#endif

#include <pthread.h>

#include "main.h"
#include "ip2mac.h"

#include "daemon.h"
#include "socket.h"
#include "packet.h"
#include "log.h"
#include "util.h"
#include "senddata.h"

//使用するインタフェース２つ
#ifndef __linux
DEVICE Device[2] = {
	{"em0"},
	{"em1"},
};
#else
DEVICE Device[2] = {
	{"eth0"},
	{"eth1"},
};
#endif


//パケットを転送する上位ルータのIP（文字列）
char *RouterIP = "192.168.100.1";
//上位ルータのIP（バイナリ）
struct in_addr NextRouter;
//スレッドの識別子（pthread_create,pthread_join時に使用）
static pthread_t BufTid;


static int SendIcmpTimeExceeded(int deviceNo, struct ether_header *eh, struct ip *iphdr, u_char *data, int size);
static void *BufThread(void *arg);
static int AnalyzePacket(int deviceNo, u_char *data, int size);
static void ReadPacket(int socket, int deviceNo);
static void Router();
void StartService();
void StopService();


static int AnalyzePacket(int deviceNo, u_char *data, int size){
	if(size < sizeof(struct ether_header *)){
		InfoLog("not ehter_header[%d]:lest=%d",deviceNo,size);
		return -1;
	}
	InfoLog("start one packet=======================================================================");
	PrintPacket(data);


	struct ether_header *eth;
	u_char *ptr;
	int lest;

	ptr = data;
	lest = size;

	eth = (struct ether_header *)ptr;
	ptr += sizeof(struct ether_header); //データの先頭ポインタ
	lest -= sizeof(struct ether_header); //データの残りサイズ

	//ルーターの場合、転送すべきパケットのMACアドレスは自分宛のものだけ。ブロードキャストは転送の必要なし。
	if(memcmp(&eth->ether_dhost, Device[deviceNo].hwaddr, 6) != 0){
		InfoLog("[info:%d]: dhost is broadcast(%s) so end", deviceNo, MacToString((u_char *)&eth->ether_dhost));
		return -1;
	}

	if(ntohs(eth->ether_type)==ETHERTYPE_ARP){
		struct ether_arp *arp;

		if(lest < sizeof(struct ether_arp)){
			InfoLog("[error:%d]:lest(%d)<sizeof(struct ether_arp)", deviceNo, lest);
			return -1;
		}
		arp = (struct ether_arp *)ptr;
		ptr += sizeof(struct ether_arp);
		lest -= sizeof(struct ether_arp);

		if(arp->arp_op == htons(ARPOP_REQUEST)){
			InfoLog("[info:%d]recv:ARP REQUEST:%dbytes,", deviceNo, size);
			Ip2Mac(deviceNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
		}else if(arp->arp_op == htons(ARPOP_REPLY)){
			InfoLog("[info:%d]recv:ARP REPLY:%dbytes,", deviceNo, size);
			Ip2Mac(deviceNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
		}
	}else if(ntohs(eth->ether_type)==ETHERTYPE_IP){
		struct ip *iphdr;
		u_char option[1500];
		int optionLen = 0;
		int tno;
		u_char hwaddr[6];
	//	char buf[80];

		if(lest < sizeof(struct ip)){
			InfoLog("[error:%d]lest(%d)<sizeof(struct ip)", deviceNo, lest);
			return -1;
		}
		iphdr = (struct ip *)ptr;
		ptr += sizeof(struct ip);
		lest -= sizeof(struct ip);

		optionLen = iphdr->ip_hl * 4 - sizeof(struct ip); //通常は0になる
		if(optionLen > 0){
			if(optionLen >= 1500){
				InfoLog("[error:%d]:IP optionLen(%d):too big", deviceNo, optionLen);
				return -1;
			}
			memcpy(option, ptr, optionLen);
			ptr += optionLen;
			lest -= optionLen;
		}

		if(checkIPchecksum(iphdr, option, optionLen)==0){
			InfoLog("[error:%d]:bad ip checksum", deviceNo);
			return -1;
		}

		//経由していいルータの数がもうなければicmpパケット飛ばして終了
		if(iphdr->ip_ttl-1 == 0){
			InfoLog("[info:%d]:iphdr->ip_ttl==0 error", deviceNo);
			SendIcmpTimeExceeded(deviceNo, eth, iphdr, data, size);
			return -1;
		}

		tno=(!deviceNo);

		//宛先IPが送出するインタフェースのサブネット内であれば、直接パケットを送る
		/*
		 *VM3(192.168.200.3/24)から192.168.100.1へpingする場合
		 *192.168.200.1/24で受信して、送出するインタフェースは192.168.100.2/24であるため
		 *同一サブネットとみなし直接宛先へパケットを送る
		 *
		 *VM3(192.168.200.3/24)から192.168.2.1へpingする場合（192.168.2.1じゃなくてもなんでもよい）
		 *192.168.200.1/24で受信して、送出するインタフェースは192.168.100.2/24であるため
		 *異なるサブネットのため上位ルータへパケットを送る（つまり下記のelseに入る）
		*/
		IP2MAC *ip2mac;
		in_addr_t dest_ip;
		if((iphdr->ip_dst.s_addr & Device[tno].netmask.s_addr) == Device[tno].subnet.s_addr){
			InfoLog("[info:%d]%s to TargetSegment", deviceNo, InetToString(&iphdr->ip_dst));

			//宛先IPが送出するインタフェースのIPと同じなら転送する必要ないのでここで終了
			if(iphdr->ip_dst.s_addr == Device[tno].addr.s_addr){
				InfoLog("[info:%d]recv:myaddr",deviceNo);
				return -1;
			}
			dest_ip = iphdr->ip_dst.s_addr;
		}else{
			InfoLog("[info:%d]%s to NextRouter", deviceNo, InetToString(&iphdr->ip_dst));
			dest_ip = NextRouter.s_addr;
		}

		/*
		 * フラグがNG、もしくはバッファにまだ未送信データが溜まってる場合
		 * 未送信バッファがある状態で下記送信処理（writeのとこ）をするとパケットの順番がおかしくなるのでAppendSendDataする
		 */
		ip2mac = Ip2Mac(tno, dest_ip, NULL);
		if(ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0){
			InfoLog("[info:%d]Ip2Mac:Notfound hwaddr or Exists SendData(%s)", deviceNo, InaddrToString(dest_ip));
			AppendSendData(ip2mac, 1, iphdr->ip_dst.s_addr, data, size);
			return -1;
		}else{
			memcpy(hwaddr, ip2mac->hwaddr, 6);
		}

		/*
		 * ip2macがNGまたは未送信バッファが残っている場合はここに到達しない（一旦バッファに溜めてreturnで終了するため）
		 * バッファに溜まったデータは別スレッドで勝手に送信される（BufferSendOne）
		 * ip2macがOKの場合のみこのまま下記送信処理をする
		 */
		//宛先MACアドレスと送信元MACアドレスを書き換える
		memcpy(eth->ether_dhost, hwaddr, 6);
		memcpy(eth->ether_shost, Device[tno].hwaddr, 6);
		//経由していいルータの数を１つ減らす
		iphdr->ip_ttl--;
		//チェックサムを計算しなおす
		iphdr->ip_sum=0;
		iphdr->ip_sum=checksum2((u_char *)iphdr, sizeof(struct ip), option, optionLen);
		//送出する
		write(Device[tno].socket, data, size);
		InfoLog("[info:%d]write:AnalyzePacket: %dbytes", deviceNo, size);
	}
	return 0;
}

static void ReadPacket(int socket, int deviceNo){
	int size = 0;
	u_char buf[8192];

#ifndef __linux
	size = read(socket, buf, sizeof(buf));
	if(size <= 0){
		ErrorLog("read");
	}else{
		InfoLog("--------size=%d,deviceNo=%d",size,deviceNo);

		int bpf_len=size;
		struct bpf_hdr *bp;
		void *data_pointer;
		int data_size;
		int one_size;
		bp = (struct bpf_hdr *)buf;
		
		while(bpf_len > 0){
			data_pointer = (char *)bp + bp->bh_hdrlen;
			data_size = bp->bh_caplen;

			AnalyzePacket(deviceNo, data_pointer, data_size);

			one_size = BPF_WORDALIGN(bp->bh_hdrlen + bp->bh_caplen);
			bpf_len -= one_size;
			bp = (struct bpf_hdr *)((void *)bp + one_size);
		}
	}
#else
	size = read(socket, buf, sizeof(buf));
	if(size <= 0){
		ErrorLog("read");
	}else{
		AnalyzePacket(deviceNo, buf, size);
	}
#endif
}

static void Router(){
	struct pollfd	targets[2];
	int nready, i;

	targets[0].fd = Device[0].socket;
	targets[0].events = POLLIN|POLLERR;
	targets[1].fd = Device[1].socket;
	targets[1].events = POLLIN|POLLERR;

	while(1){
		switch(nready = poll(targets,2,100)){
		case	-1:
			if(errno != EINTR){
				ErrorLog("poll");
				exit(EXIT_FAILURE);
			}
			break;
		case	0:
			break;
		default:
			for(i=0; i<=1; i++){
				if(targets[i].revents&(POLLIN|POLLERR)){
					ReadPacket(targets[i].fd,i);
				}
			}
			break;
		}
	}
}

static void *BufThread(void *arg){
	BufferSend();
	return NULL;
}

void StartService(){
	pthread_attr_t attr;
	int status;

	inet_aton(RouterIP, &NextRouter);
	InfoLog("top router=%s",RouterIP);

	int i;
	for(i=0; i<2; i++){
		if(GetDeviceInfo(Device[i].ifname, Device[i].hwaddr, &Device[i].addr, &Device[i].subnet, &Device[i].netmask) == -1){
			ErrorLog("DeviceInfo Error");exit(EXIT_FAILURE);
		}
		InfoLog("-----dev=%s",Device[i].ifname);
		InfoLog("ethaddr=%s",MacToString(Device[i].hwaddr));
		InfoLog("addr=%s", InetToString(&Device[i].addr));
		InfoLog("subnet=%s", InetToString(&Device[i].subnet));
		InfoLog("netmask=%s", InetToString(&Device[i].netmask));

		if((Device[i].socket=InitRawSocket(Device[i].ifname, 0, 0)) == -1){
			ErrorLog("InitRawSocket Error");exit(EXIT_FAILURE);
		}
	}

	pthread_attr_init(&attr);
	if((status=pthread_create(&BufTid, &attr, BufThread, NULL))!=0){
		InfoLog("[error]ptherd_create:%s",strerror(status));
	}

InfoLog("BufTid start=%d",BufTid);
	InfoLog("start router");
	Router();
}

void StopService(){
	InfoLog("stop router");
InfoLog("BufTid end=%d",BufTid);
//	pthread_join(BufTid, NULL);
	int i;
	for(i=0; i<2; i++){
		close(Device[i].socket);
	}
}


int main(int argc, char *argv[], char *envp[]){
	char *mode;

	chdir(SERVER_ROOT);

	if(argc == 2){
		mode = argv[1];
		if(strcmp(mode,"start")==0){
			StartServer();
		}else if(strcmp(mode,"stop")==0){
			StopServer();
		}else if(strcmp(mode,"restart")==0){
			StopServer();
			StartServer();
		}else{
			printf("usage: start stop restart\n");
			exit(EXIT_FAILURE);
		}
	}else{
		printf("usage: start stop restart\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

#include <netinet/ip_icmp.h>
static int SendIcmpTimeExceeded(int deviceNo, struct ether_header *eh, struct ip *iphdr, u_char *data, int size){
	struct ether_header reh;
	struct ip rih;
	struct icmp icmp;
	u_char *ipptr;
	u_char *ptr, buf[1500];
	int len;

	memcpy(reh.ether_dhost, eh->ether_shost, 6);
	memcpy(reh.ether_shost, Device[deviceNo].hwaddr, 6);
	reh.ether_type = htons(ETHERTYPE_IP);

	rih.ip_v = 4;
	rih.ip_hl = 20 / 4;
	rih.ip_tos = 0;
	rih.ip_len = htons(sizeof(struct icmp) + 64);
	rih.ip_id = 0;
	rih.ip_off = 0;
	rih.ip_ttl = 64;
	rih.ip_p = IPPROTO_ICMP;
	rih.ip_sum = 0;
	rih.ip_src.s_addr = Device[deviceNo].addr.s_addr;
	rih.ip_dst.s_addr = iphdr->ip_src.s_addr;

	rih.ip_sum = checksum((u_char *)&rih, sizeof(struct ip));

	icmp.icmp_type = ICMP_TIMXCEED;
	icmp.icmp_code = ICMP_TIMXCEED_INTRANS;
	icmp.icmp_cksum = 0;
	icmp.icmp_void = 0;

	ipptr = data + sizeof(struct ether_header);

	icmp.icmp_cksum = checksum2((u_char *)&icmp, 8, ipptr, 64);

	ptr = buf;
	memcpy(ptr, &reh, sizeof(struct ether_header));
	ptr += sizeof(struct ether_header);
	memcpy(ptr, &rih, sizeof(struct ip));
	ptr += sizeof(struct ip);
	memcpy(ptr, &icmp, 8);
	ptr += 8;
	memcpy(ptr, ipptr, 64);
	ptr += 64;
	len = ptr - buf;

	write(Device[deviceNo].socket, buf, len);
	InfoLog("[info:%d]SendIcmpTimeExceeded: %dbytes", deviceNo, len);

	return 0;
}