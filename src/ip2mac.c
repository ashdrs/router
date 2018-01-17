#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/time.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>


#include "ip2mac.h"
#include "util.h"
#include "log.h"
#include "senddata.h"

#define	IP2MAC_TIMEOUT_SEC		60
#define	IP2MAC_NG_TIMEOUT_SEC	1

struct {
	IP2MAC	*data;	//対象IPアドレスごとのデータ
	int		size;	//領域確保済みデータ数
	int		no;		//データ数
}Ip2Macs[2];

extern DEVICE	Device[2];

static int AppendSendBuffer(int deviceNo, int ip2macNo);
static int BufferSendOne(int deviceNo,IP2MAC *ip2mac);
static int GetSendBufferNo(int *deviceNo,int *ip2macNo);

/*
 *ip2macの検索と登録を１つの関数でやってる
 */
IP2MAC *Ip2MacSearch(int deviceNo, in_addr_t addr, u_char *hwaddr){
	register int i;
	int freeNo, no;
	time_t now;
//	char buf[80];
	IP2MAC *ip2mac;

	freeNo=-1;
	now=time(NULL);

	for(i=0; i<Ip2Macs[deviceNo].no; i++){
		ip2mac=&Ip2Macs[deviceNo].data[i];
		if(ip2mac->flag==FLAG_FREE){ //ip2macが空き状態だったら
			if(freeNo==-1){ //まだ空きNoが見つかってなかったら
				freeNo=i; //空きNoをfreeNoにもつ
			}
			continue;
		}
		if(ip2mac->addr==addr){ //引数のIPと同じip2macが見つかれば。
			if(ip2mac->flag==FLAG_OK){ //ip2macが使用可能状態なら
				ip2mac->lastTime=now; //時刻を今の時間に更新
			}
			if(hwaddr!=NULL){
				//引数のhwaddrがNULLじゃなければip2macに登録してOKフラグを立ててip2macを返す
				memcpy(ip2mac->hwaddr, hwaddr, 6);
				ip2mac->flag=FLAG_OK;
				if(ip2mac->sd.top != NULL){
					AppendSendBuffer(deviceNo, i);
				}
				return ip2mac;
			}else{
				/*
				 * フラグはOKだけど、有効期間を過ぎてるか（有効期間＝「最後に使用」された時間からIP2MAC_TIMEOUT_SEC秒）
				 * もしくは、hwaddrをもってない状態での期限がきれた場合解放する。そうじゃなければそのままip2macを返す
				 *※ここではフラグがOKだと上で最終日時を更新してるため下記の前者条件には当てはまることはない
				 */
				if((ip2mac->flag==FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC) ||
					(ip2mac->flag==FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC))
				{
					FreeSendData(ip2mac);
					ip2mac->flag=FLAG_FREE;
					if(freeNo==-1){
						freeNo=i;
					}
				}else{
					return ip2mac;
				}
			}
		}else{
			/*
			 * 上の処理と全く同じタイムアウトチェックによる解放処理
			 * ※ここではフラグがOKでも最終日時を更新してないので下記前者条件に当てはまる
			 */
			if((ip2mac->flag==FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC) ||
				(ip2mac->flag==FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC))
			{
				FreeSendData(ip2mac);
				ip2mac->flag=FLAG_FREE;
				if(freeNo==-1){
					freeNo=i;
				}
			}
		}
	}

	if(freeNo==-1){ //確保したip2macリストに空きがない場合
		no=Ip2Macs[deviceNo].no;
		if(no >= Ip2Macs[deviceNo].size){ //今ある個数(no) >= メモリ確保済の個数->新たな確保が必要
			if(Ip2Macs[deviceNo].size==0){ //一番最初（まだIp2Macsが空のとき）
				//初期値1024個
				Ip2Macs[deviceNo].size=1024;
				//1024個分確保
				Ip2Macs[deviceNo].data=(IP2MAC *)malloc(1024 * sizeof(IP2MAC));
			}else{
				//1024個追加
				Ip2Macs[deviceNo].size+=1024;
				//1024個追加分のメモリ確保
				Ip2Macs[deviceNo].data=(IP2MAC *)realloc(Ip2Macs[deviceNo].data, Ip2Macs[deviceNo].size * sizeof(IP2MAC));
			}
		}
		Ip2Macs[deviceNo].no++;
	}else{
		no=freeNo;
	}

	//対象のip2macが見つからなかったので追加処理
	ip2mac=&Ip2Macs[deviceNo].data[no]; //対象のip2mac

	ip2mac->deviceNo=deviceNo;
	ip2mac->addr=addr; //IPアドレス
	if(hwaddr==NULL){
		ip2mac->flag=FLAG_NG; //MACアドレスがわからないのでNG
		memset(ip2mac->hwaddr, 0, 6);
	}else{
		ip2mac->flag=FLAG_OK; //MACアドレス判明してるのでOK
		memcpy(ip2mac->hwaddr, hwaddr, 6);
	}
	ip2mac->lastTime=now;
	memset(&ip2mac->sd, 0, sizeof(SEND_DATA));
	pthread_mutex_init(&ip2mac->sd.mutex, NULL); //登録時にmutexをinitしておく

	InfoLog("[info:%d]Ip2Mac Add %s = %d", deviceNo, InaddrToString(ip2mac->addr), no);

	return ip2mac;
}


/*
 *ARPパケットのときはhwaddrありでIP2MACテーブルへの登録として実行される
 *IPパケットのときはhwaddrはNULLでMACアドレスを知るためip2mac構造体をもらう
*/
IP2MAC *Ip2Mac(int deviceNo, in_addr_t addr, u_char *hwaddr){
	IP2MAC *ip2mac;
	static u_char bcast[6]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//	char buf[80];

	//対象IPアドレスのデータ検索
	ip2mac=Ip2MacSearch(deviceNo, addr, hwaddr);
	if(ip2mac->flag==FLAG_OK){
		InfoLog("[info:%d]Ip2Mac(%s):OK", deviceNo, InaddrToString(addr));
	}else{
		//hwaddrがないのでARPリクエスト送信
		InfoLog("[info:%d]Ip2Mac Not found hwaddr(%s): Send ARP REQUEST", deviceNo, InaddrToString(addr));
		SendArpRequest(Device[deviceNo].socket, addr, bcast, Device[deviceNo].addr.s_addr, Device[deviceNo].hwaddr);
	}
	return ip2mac;
}





//MACアドレスがわかって送信可能なデータ
typedef struct _send_req_data_ {
	struct _send_req_data_	*next;		//前のデータ
	struct _send_req_data_	*before;	//次のデータ
	int deviceNo;						//デバイス番号
	int ip2macNo;						//データ番号：Ip2Macs[デバイス番号].data[ip2macNo]
}SEND_REQ_DATA;

/*
 * 送信待ちデータ
 * condはpthread_cond_init関数で初期化できるがPTHREAD_COND_INITIALIZER定数で
 * 静的に初期化することもできる。mutexについても同様である。
 */
struct {
	SEND_REQ_DATA	*top;		//送信待ちデータ先頭ポインタ
	SEND_REQ_DATA	*bottom;	//送信待ちデータ末尾ポインタ
	pthread_mutex_t	mutex;		//排他用ミューテックス
	pthread_cond_t	cond;		//条件変数
}SendReq={NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

/*
#include "senddata.h"
static void ViewSendReqData(int deviceNo){ //デバッグ用
	IP2MAC ip2mac;
	SEND_REQ_DATA *datap;

	datap = SendReq.top;
	ip2mac = Ip2Macs[deviceNo].data[datap->ip2macNo];
	ViewSendData(&ip2mac);
	while(datap->next!=NULL){
		datap = datap->next;

		ip2mac = Ip2Macs[deviceNo].data[datap->ip2macNo];
		ViewSendData(&ip2mac);
	}
	
}
*/

/*
 *ARP解決して転送可能なデータを追加
 */
static int AppendSendBuffer(int deviceNo, int ip2macNo){
	SEND_REQ_DATA	*d;
	int status;

	//転送待ちデータをロックする
	if((status=pthread_mutex_lock(&SendReq.mutex))!=0){
		InfoLog("[error:%d]AppendSendBuffer:pthread_mutex_lock:%s", deviceNo, strerror(status));
		return -1;
	}

	//すでに転送可能データリストにいればOKだからなにもしない
	for(d=SendReq.top; d!=NULL; d=d->next){
		if(d->deviceNo==deviceNo && d->ip2macNo==ip2macNo){
			pthread_mutex_unlock(&SendReq.mutex); //送信待ちデータのロックを解放
			return 1;
		}
	}

	d=(SEND_REQ_DATA *)malloc(sizeof(SEND_REQ_DATA));
	if(d==NULL){
		InfoLog("[error:%d]AppendSendBuffer:malloc",deviceNo);
		pthread_mutex_unlock(&SendReq.mutex); //送信待ちデータのロックを解放
		return -1;
	}
	d->next=d->before=NULL;
	d->deviceNo=deviceNo;
	d->ip2macNo=ip2macNo; //Ip2Macs.dataのキー（対象ip2macのキー）

	if(SendReq.bottom==NULL){
		//まだSendreqの末尾ポインタがNULLの場合（つまり一番最初のデータの場合）
		//先頭ポインタも末尾ポインタも今回作成したSEND_REQ_DATAのポインタ
		SendReq.top=SendReq.bottom=d;
	}else{
		//すでにデータを保持していた場合
		SendReq.bottom->next=d; //末尾データの次のデータは今回追加するデータ
		d->before=SendReq.bottom; //今回追加するデータの前のデータは末尾データ
		SendReq.bottom=d; //末尾データを今回追加したデータにする
	}
	pthread_cond_signal(&SendReq.cond); //pthread_cond_timedwaitで待機中の部分に実行OKのシグナル送信
	pthread_mutex_unlock(&SendReq.mutex); //送信待ちデータのロックを解放

	InfoLog("[info:%d]AppendSendBuffer: %d", deviceNo, ip2macNo);
//	InfoLog("ViewSendReqData"); //デバッグ用
//	ViewSendReqData(deviceNo); //デバッグ用

	return 0;
}

/*
 * ip2macがOKで（送信可能で）送信待ちになっているバッファを取得する
 */
static int GetSendBufferNo(int *deviceNo, int *ip2macNo){
	SEND_REQ_DATA	*d;
	int status;

	//バッファがなければ終了
	if(SendReq.top==NULL){
		return -1;
	}

	//送信待ちデータをロックする
	if((status=pthread_mutex_lock(&SendReq.mutex))!=0){
		InfoLog("[[error:%d]]pthread_mutex_lock:%s", deviceNo, strerror(status));
		return -1;
	}
	d=SendReq.top; //一番最初のデータ（deviceNo,ip2macNo）を格納
	SendReq.top=d->next; //一番最初のデータを次のデータにする
	if(SendReq.top==NULL){ //次のデータがなければ
		SendReq.bottom=NULL; //もうデータは残ってないのでbottomもNULLにする
	}else{
		SendReq.top->before=NULL; //前のデータ、つまり今回取得したdはバッファからなくなるのでNULLにする
	}
	pthread_mutex_unlock(&SendReq.mutex); //送信待ちデータのロックを解放する

	*deviceNo=d->deviceNo;
	*ip2macNo=d->ip2macNo;

	InfoLog("[[info:%d]]GetSendBufferNo:ip2macNo=%d", *deviceNo, *ip2macNo);

	return 0;
}

//送信可能バッファを送信する
static int BufferSendOne(int deviceNo, IP2MAC *ip2mac){
	struct ether_header eth;
	struct ip iphdr;
	u_char option[1500];
	int optionLen;
	int size;
	u_char *data;
	u_char *ptr;

	while(1){
		if(GetSendData(ip2mac, &size, &data)==-1){
			break;
		}

		ptr=data;

		memcpy(&eth, ptr, sizeof(struct ether_header));
		ptr+=sizeof(struct ether_header);
		memcpy(&iphdr, ptr, sizeof(struct ip));
		ptr+=sizeof(struct ip);

		optionLen=iphdr.ip_hl * 4 - sizeof(struct ip);
		if(optionLen > 0){
			memcpy(option, ptr, optionLen);
			ptr+=optionLen;
		}

		//宛先MACアドレスを書き換える
		memcpy(eth.ether_dhost, ip2mac->hwaddr, 6);
		memcpy(data, &eth, sizeof(struct ether_header));
		//経由していいルータの数を１つ減らす
		iphdr.ip_ttl--;
		//チェックサムを計算しなおす
		iphdr.ip_sum=0;
		iphdr.ip_sum=checksum2((u_char *)&iphdr, sizeof(struct ip), option, optionLen);
		memcpy(data+sizeof(struct ether_header), &iphdr, sizeof(struct ip));
		//送出する
		write(Device[deviceNo].socket, data, size);
		InfoLog("[[info:%d]]write:BufferSendOne: %dbytes ttl %d->%d", deviceNo, size, iphdr.ip_ttl, iphdr.ip_ttl-1);
	}
	return 0;
}

/*
 * この関数は別スレッドで実行されるので整合性担保のためmutex制御が必要
 */
int BufferSend(){
	InfoLog("BufferSend Start");

	struct timeval now;
	struct timespec timeout;
	int deviceNo, ip2macNo;
	int status;

	while(1){
		gettimeofday(&now, NULL);
		timeout.tv_sec=now.tv_sec+1;
		timeout.tv_nsec=now.tv_usec*1000;

		//送信待ちデータをロックする
		pthread_mutex_lock(&SendReq.mutex);
		//親スレッドから指示を出すまで子スレッド（このスレッド）に止まっていて欲しい
		//pthread_cond_signalで指示がくるか、タイムアウトするまで待機
		if((status=pthread_cond_timedwait(&SendReq.cond, &SendReq.mutex, &timeout))!=0){
		//	InfoLog("[[info]]pthread_cond_timedwait NG:%s", strerror(status));
		}else{
			//AppendSendBuffer内でpthread_cond_signalが実行されたらここを通る
			InfoLog("[[info]]pthread_cond_timedwait OK:%d", status);
		}
		//送信待ちデータのロックを解放する
		pthread_mutex_unlock(&SendReq.mutex);
		
		while(1){
			//送信可能なデータのdeviceNoとIp2Macsのデータのキーを取得する
			if(GetSendBufferNo(&deviceNo, &ip2macNo)==-1){
				break;
			}
			//送信可能データを送信する
			BufferSendOne(deviceNo, &Ip2Macs[deviceNo].data[ip2macNo]);
		}
	}

	InfoLog("BufferSend End");

	return 0;
}


