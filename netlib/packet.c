#include <unistd.h>

//for freebsd
#include <netinet/in.h>

#include <sys/socket.h>
#include <netinet/ip.h>

#include <netinet/ip_icmp.h>
#define __FAVOR_BSD //for Linux
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "log.h"
#include "util.h"

#include "packet.h"


static void PrintEthernet(struct ether_header *eth);
static void PrintArp(struct ether_arp *arp);
static void PrintIp(struct ip *ip);
static void PrintTcp(struct tcphdr *tcp);
static void PrintTcpMini(struct tcphdr *tcp);
static void PrintUdp(struct udphdr *udp);
static void PrintIcmp(struct icmp *icmp);
static char *ip_ttoa(int flag);
static char *ip_ftoa(int flag);
static char *tcp_ftoa(int flag);


void PrintPacket(void *data){
	void *p;
	struct ether_header *eth;
	struct ether_arp *arp;		//ARPパケット構造体
	struct ip *ip;				//IPヘッダ構造体
	struct icmp *icmp;			//ICMPパケット構造体
	struct tcphdr *tcp;			//TCPヘッダ構造体
	struct udphdr *udp;			//UDPヘッダ構造体

	p = data;

	eth = (struct ether_header *)p;
	p += sizeof(struct ether_header);
	PrintEthernet(eth);

	if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
		arp = (struct ether_arp *) p;
		PrintArp(arp);
	}else if(ntohs(eth->ether_type) == ETHERTYPE_IP){
		ip = (struct ip *) p;
		p += ((int) (ip->ip_hl) << 2);

		switch(ip->ip_p){
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) p;
			p += ((int) (tcp->th_off) << 2);
			break;
		case IPPROTO_UDP:
			udp = (struct udphdr *) p;
			p += sizeof (struct udphdr);
			break;
		case IPPROTO_ICMP:
			icmp = (struct icmp *) p;
			p = icmp->icmp_data;
			break;
		default:
			break;
		}

		PrintIp(ip);
		if(ip->ip_p == IPPROTO_TCP){
			PrintTcp(tcp);
		}else if(ip->ip_p == IPPROTO_UDP){
			PrintUdp(udp);
		}else if(ip->ip_p == IPPROTO_ICMP){
			PrintIcmp(icmp);
		}else{
			InfoLog("Protocol: unknown\n");
		}
	}
}

/*
 * void PrintEthernet(struct ether_header *eth);
 * 機能　Ethernetヘッダの表示
 * 引数　struct ether_header *eth; Ethernetヘッダ構造体のポインタ
 * 戻り値　なし
 */
static void PrintEthernet(struct ether_header *eth){
	int type = ntohs(eth->ether_type); //Ethernetタイプ

	if(type <= 1500){ //1500 == 0x05dc
		InfoLog("IEEE 802.3 Ethernet Frame:");
	}else{
		InfoLog("Ethernet Frame:");
	}
	InfoLog("+---------------------------+-----------------------+");
	InfoLog("| Source MAC Address:              %17s|", MacToString(eth->ether_shost));
	InfoLog("+---------------------------+-----------------------+");
	InfoLog("| Destination MAC Address:         %17s|", MacToString(eth->ether_dhost));
	InfoLog("+---------------------------+-----------------------+");
	if(type < 1500){
		InfoLog("| Length:            %5u|", type);
	}else{
		InfoLog("| Ethernet Type:      0x%04x|", type);
	}
	InfoLog("+---------------------------+");
}


/*
 * void PrintArp(struct ether_arp *arp);
 * 機能　ARPパケットの表示
 * 引数　struct ether_arp *arp; ARPパケット構造体のポインタ
 * 戻り値　なし
 */
static void PrintArp(struct ether_arp *arp){
	static char *arp_op_name[] = {
		"Undefine",
		"(ARP Request)",
		"(ARP Reply)",
		"(RARP Request)",
		"(RARP Reply)",
	};
	#define ARP_OP_MAX (sizeof arp_op_name / sizeof arp_op_name[0])

	int op = ntohs(arp->ea_hdr.ar_op); //ARPオペレーション
	if(op < 0 || ARP_OP_MAX < op){
		op = 0;
	}
	InfoLog("Protocol: ARP");
	InfoLog("+--------------------------+------------------------+");
	InfoLog("| Hard Type: %2u%-11s| Protocol:0x%04x%-9s|",
			ntohs(arp->ea_hdr.ar_hrd),
			(ntohs(arp->ea_hdr.ar_hrd)==ARPHRD_ETHER)?"(Ethernet)":"(Not Ether)",
			ntohs(arp->ea_hdr.ar_pro),
			(ntohs(arp->ea_hdr.ar_pro)==ETHERTYPE_IP)?"(IP)":"(Not IP)");
	InfoLog("+------------+-------------+------------------------+");
	InfoLog("| HardLen:%3u| Addr Len:%2u| OP: %4d%16s|",
			arp->ea_hdr.ar_hln, arp->ea_hdr.ar_pln, ntohs(arp->ea_hdr.ar_op),
			arp_op_name[op]);
	InfoLog("+------------+-------------+------------------------+");
	InfoLog("| Source MAC Address:              %17s|", MacToString(arp->arp_sha));
	InfoLog("+---------------------------------------------------+");
	InfoLog("| Source IP Address:                 %15s|",inet_ntoa(*(struct in_addr *) &arp->arp_spa));
	InfoLog("+---------------------------------------------------+");
	InfoLog("| Destination MAC Address:         %17s|", MacToString(arp->arp_tha));
	InfoLog("+---------------------------------------------------+");
	InfoLog("| Destination IP Address:            %15s|",inet_ntoa(*(struct in_addr *) &arp->arp_tpa));
	InfoLog("+---------------------------------------------------+");
}

/*
 * void PrintIp(struct ip *ip);
 * 機能　IPヘッダの表示
 * 引数　struct ip *ip; IPヘッダ構造体のポインタ
 * 戻り値　なし
 */
static void PrintIp(struct ip *ip){
	InfoLog("Protocol: IP");
	InfoLog("+-----+------+------------+-------------------------+");
	InfoLog("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|",
			ip->ip_v, ip->ip_hl, ip_ttoa(ip->ip_tos), ntohs(ip->ip_len));
	InfoLog("+-----+------+------------+-------+-----------------+");
	InfoLog("| Identifier:        %5u| FF:%3s| FO:        %5u|",
			ntohs(ip->ip_id), ip_ftoa(ntohs(ip->ip_off)),
			ntohs(ip->ip_off) &IP_OFFMASK);
	InfoLog("+------------+------------+-------+-----------------+");
	InfoLog("| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|",
			ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum));
	InfoLog("+------------+------------+-------------------------+");
	InfoLog("| Source IP Address:                 %15s|",
			inet_ntoa(*(struct in_addr *) &(ip->ip_src)));
	InfoLog("+---------------------------------------------------+");
	InfoLog("| Destination IP Address:            %15s|",
			inet_ntoa(*(struct in_addr *) &(ip->ip_dst)));
	InfoLog("+---------------------------------------------------+");
}

/*
 * void PrintTcp(struct tcphdr *tcp);
 * 機能　TCPヘッダの表示
 * 引数　struct tcphdr *tcp; TCPヘッダ構造体
 * 戻り値　なし
 */
static void PrintTcp(struct tcphdr *tcp){
	InfoLog("Protocol: TCP");
	InfoLog("+-------------------------+-------------------------+");
	InfoLog("| Source Port:       %5u| Destination Port:  %5u|",
			ntohs(tcp->th_sport), ntohs(tcp->th_dport));
	InfoLog("+-------------------------+-------------------------+");
	InfoLog("| Sequence Number:                        %10lu|",
			(unsigned long) ntohl(tcp->th_seq));
	InfoLog("+---------------------------------------------------+");
	InfoLog("| Acknowledgement Number:                 %10lu|",
			(unsigned long) ntohl(tcp->th_ack));
	InfoLog("+---------------------------------------------------+");
	InfoLog("| DO:%2u | Reserved|F:%6s| Window Size:      %5u|",
			tcp->th_off, tcp_ftoa(tcp->th_flags), ntohs(tcp->th_win));
	InfoLog("+------+---------+--------+-------------------------+");
	InfoLog("| Checksum:          %5u| Urgent Pointer:    %5u|",
			ntohs(tcp->th_sum), ntohs(tcp->th_urp));
	InfoLog("+-------------------------+-------------------------+");
}

/*
 * void PrintTcpMini(struct tcphdr *tcp);
 * 機能　TCPヘッダの先頭の64ビットの表示（ICMPで返送される部分）
 * 引数　struct tcphdr *tcp; TCPヘッダ構造体
 * 戻り値　なし
 */
static void PrintTcpMini(struct tcphdr *tcp){
	InfoLog("Protocol: TCP");
	InfoLog("+-------------------------+-------------------------+");
	InfoLog("| Source Port:       %5u| Destination Port:  %5u|",
			ntohs(tcp->th_sport), ntohs(tcp->th_dport));
	InfoLog("+-------------------------+-------------------------+");
	InfoLog("| Sequence Number:                        %10lu|",
			(unsigned long) ntohl(tcp->th_seq));
	InfoLog("+---------------------------------------------------+");
}

/*
 * void PrintUdp(struct udphdr *udp);
 * 機能　UDPヘッダを表示
 * 引数　struct udphdr *udp; UDPヘッダ構造体のポインタ
 * 戻り値　なし
 */
static void PrintUdp(struct udphdr *udp){
	InfoLog("Protocol: UDP");
	InfoLog("+-------------------------+-------------------------+");
	InfoLog("| Source Port:       %5u| Destination Port:  %5u|",
			ntohs(udp->uh_sport), ntohs(udp->uh_dport));
	InfoLog("+-------------------------+-------------------------+");
	InfoLog("| Length:            %5u| Checksum:          %5u|",
			ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
	InfoLog("+---------------------------------------------------+");
}

/*
 * void PrintIcmp(struct icmp *icmp);
 * 機能　ICMPヘッダ・データの表示
 * 引数　struct icmp *icmp; ICMPヘッダ構造体のポインタ
 * 戻り値　なし
 */
static void PrintIcmp(struct icmp *icmp){
	static char *type_name[] = {
		"Echo Reply",				//Type 0
		"Undefine",					//Type 1
		"Undefine",					//Type 2
		"Destination Unreachable",	//Type 3
		"Source Quench",			//Type 4
		"Redirect (change route)",	//Type 5
		"Undefine",					//Type 6
		"Undefine",					//Type 7
		"Echo Request",				//Type 8
		"Undefine",					//Type 9
		"Undefine",					//Type 10
		"Time Exceeded",			//Type 11
		"Parameter Problem",		//Type 12
		"Timestamp Request",		//Type 13
		"Timestamp Reply",			//Type 14
		"Information Request",		//Type 15
		"Information Reply",		//Type 16
		"Address Mask Request",		//Type 17
		"Address Mask Reply",		//Type 18
		"Unknown",					//Type 19
	};
	#define ICMP_TYPE_MAX (sizeof type_name / sizeof type_name[0])

	int type = icmp->icmp_type; //ICMPタイプ

	if(type < 0 || ICMP_TYPE_MAX <= type){
		type = ICMP_TYPE_MAX - 1;
	}
	InfoLog("Protocol: ICMP (%s)", type_name[type]);

	InfoLog("+------------+------------+-------------------------+");
	InfoLog("| Type:   %3u| Code:   %3u| Checksum:          %5u|",
			icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum));
	InfoLog("+------------+------------+-------------------------+");

	if(icmp->icmp_type == 0 || icmp->icmp_type == 8){
		InfoLog("| Identification:    %5u| Sequence Number:   %5u|",
				ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
		InfoLog("+--------------------------+------------------------+");
	}else if(icmp->icmp_type == 3){
		if(icmp->icmp_code == 4){
			InfoLog("| void:          %5u| Next MTU:          %5u|",
				ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu));
			InfoLog("+-------------------------+----------------------+");
		}else{
			InfoLog("| Unused:                                 %10lu|",
				(unsigned long) ntohl(icmp->icmp_void));
			InfoLog("+-------------------------+----------------------+");
		}
	}else if(icmp->icmp_type == 5){
		InfoLog("| Router IP Address:                %15s|",
				inet_ntoa(*(struct in_addr *) &(icmp->icmp_gwaddr)));
		InfoLog("+----------------------------------------------------+");
	}else if(icmp->icmp_type == 11){
		InfoLog("| Unused:                                  %10lu|",
				(unsigned long) ntohl(icmp->icmp_void));
		InfoLog("+----------------------------------------------------+");
	}

	//ICMPの後ろに、IPヘッダとトランスポートヘッダが続く場合の処理
	if(icmp->icmp_type == 3 || icmp->icmp_type == 5 || icmp->icmp_type == 11){
		struct ip *ip = (struct ip *) icmp->icmp_data;		//IPヘッダ
		char *p = (char *) ip + ((int) (ip->ip_hl) << 2);	//トランスポートヘッダ

		PrintIp(ip);
		switch(ip->ip_p){
			case IPPROTO_TCP:
				PrintTcpMini((struct tcphdr *) p);
				break;
			case IPPROTO_UDP:
				PrintUdp((struct udphdr *) p);
				break;
		}
	}
}

/*
 * char *ip_ttoa(int flag);
 * 機能　IPヘッダのTOSフィールドを文字列に変換
 *       static変数を使用しているため、非リエントラント関数
 * 引数　int flag; TOSフィールドの値
 * 戻り値　char * 変換された文字列
 */
static char *ip_ttoa(int flag){
	static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
	#define TOS_MAX (sizeof f / sizeof f[0])
	static char str[TOS_MAX + 1];	//戻り値を格納するバッファ
	unsigned int mask = 0x80;		//TOSフィールドを取り出すマスク
	int i;

	for(i = 0; i < TOS_MAX; i++){
		if(((flag << i) & mask) != 0){
			str[i] = f[i];
		}else{
			str[i] = '0';
		}
	}
	str[i] = '\0';
	return str;
}
/*
 * char *ip_ftoa(int flag);
 * 機能　IPヘッダのフラグメントビットを文字列に変換
 *     　static変数を使用しているため、非リエントラント関数
 * 引数　int flag; フラグメントフィールドの値
 * 戻り値　char * 変換された文字列
 */
static char *ip_ftoa(int flag){
	static int f[] = {'R', 'D', 'M'}; //フラグメントフラグを表す文字
	#define IP_FLG_MAX (sizeof f / sizeof f[0])
	static char str[IP_FLG_MAX + 1];	//戻り値を格納するバッファ
	unsigned int mask = 0x8000;			//マスク
	int i;

	for(i = 0; i < IP_FLG_MAX; i++){
		if(((flag << i) & mask) != 0){
			str[i] = f[i];
		}else{
			str[i] = '0';
		}
	}
	str[i] = '\0';
	return str;
}

/*
 * char *tcp_ftoa(int flag);
 * 機能　TCPヘッダのコントロールフラグを文字列に変換
 * 引数　int flag; TCPのコントロールフラグ
 * 戻り値　char * 変換された文字列
 */
static char *tcp_ftoa(int flag){
	static int f[] = {'U', 'A', 'P', 'R', 'S', 'F'}; //TCPフラグを表す文字
	#define TCP_FLG_MAX (sizeof f / sizeof f[0])
	static char str[TCP_FLG_MAX + 1];			//戻り値を格納するバッファ
	unsigned int mask = 1 << (TCP_FLG_MAX - 1);	//フラグを取り出すマスク
	int i;

	for(i = 0; i < TCP_FLG_MAX; i++){
		if(((flag << i) & mask) != 0){
			str[i] = f[i];
		}else{
			str[i] = '0';
		}
	}
	str[i] = '\0';
	return str;
}
