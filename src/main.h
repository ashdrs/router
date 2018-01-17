
#ifndef	MAIN_H
#define	MAIN_H

#include <pthread.h>
#include <netinet/in.h>
#include <unistd.h>

#define	SERVER_ROOT	"./"
#define	PID_FILE	"./router.pid"
#define	LOG_FILE	"./router.log"


#define FLAG_FREE	0	//空き
#define FLAG_OK		1	//hwaddr有り
#define FLAG_NG		-1	//hwaddrなし

typedef struct _data_buf_{
	struct _data_buf_ *next;	//次のデータ
	struct _data_buf_ *before;	//前のデータ
	time_t t;					//格納日時
	int size;					//データサイズ
	unsigned char *data;		//データ
}DATA_BUF;

//まだMACアドレス不明のデータ
typedef struct {
	DATA_BUF *top;				//送信バッファ先頭ポインタ
	DATA_BUF *bottom;			//送信バッファ末尾ポインタ
	unsigned long dno;			//送信バッファ数
	unsigned long inBucketSize;	//送信バッファ総サイズ
	pthread_mutex_t mutex;		//排他用ミューテックス
}SEND_DATA;

//ARPテーブル＆送信パケット
typedef struct {
	int flag;					//FLAG_FREE,FLAG_OK,FLAG_NG
	int deviceNo;				//デバイス番号
	in_addr_t addr;				//対象IPアドレス
	unsigned char hwaddr[6];	//対象MACアドレス
	time_t lastTime;			//最終更新日時
	SEND_DATA sd;				//送信するパケット用バッファ
}IP2MAC;

typedef struct {
	char	ifname[64];
	int		socket;
	u_char	hwaddr[6];
	struct	in_addr addr, subnet, netmask;
}DEVICE;


#endif	//MAIN_H