#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "senddata.h"

#include "log.h"
#include "util.h"

#define MAX_BUCKET_SIZE (1024 * 1024) //1つの送信待ちバッファに格納される最大容量

#include "packet.h"

void ViewSendData(IP2MAC *ip2mac){ //デバッグ用
	SEND_DATA	*sd=&ip2mac->sd;
	DATA_BUF *datap=NULL;
	int i;

	datap = sd->top;
	PrintPacket(datap->data);
	for(i=1; i < sd->dno; i++){
		datap = datap->next;
		PrintPacket(datap->data);
	}
}

int AppendSendData(IP2MAC *ip2mac, int deviceNo, in_addr_t addr, unsigned char *data, int size){
	SEND_DATA	*sd=&ip2mac->sd;
	DATA_BUF	*d;
	int status;
//	char buf[80];

	//最大容量を超えるためパケットの転送を諦めて捨てる
	if(sd->inBucketSize > MAX_BUCKET_SIZE){
		InfoLog("[error:%d]AppendSendData:Bucket overflow",deviceNo);
		return -1;
	}

	d=(DATA_BUF *)malloc(sizeof(DATA_BUF));
	if(d==NULL){
		ErrorLog("malloc");
		return -1;
	}

	//引数sizeはBPFで受信したパケットのサイズ
	d->data=(u_char *)malloc(size);
	if(d->data==NULL){
		ErrorLog("malloc");
		free(d); //DATA_BUF用に確保したメモリを解放
		return -1;
	}
	d->next=d->before=NULL;
	d->t=time(NULL); //現在時刻
	d->size=size; //受信パケットサイズ
	memcpy(d->data, data, size); //受信パケット本体

	/*
	 *線形データのポインタにずれが生じたら困るためmutex_lockをかけて処理する
	 */
	if((status=pthread_mutex_lock(&sd->mutex))!=0){
		InfoLog("[error:%d]AppendSendData:pthread_mutex_lock:%s", deviceNo, strerror(status));
		free(d->data); //受信パケット格納用に確保したメモリを解放
		free(d); //DATA_BUF用に確保したメモリを解放
		return -1;
	}
	if(sd->bottom==NULL){
		//まだSEND_DATAの末尾ポインタがNULLの場合（つまり一番最初のデータの場合）
		//先頭ポインタも末尾ポインタも今回作成したDATA_BUFのポインタ
		sd->top=sd->bottom=d;
	}else{
		//すでにデータを保持していた場合
		sd->bottom->next=d; //末尾データの次のデータは今回追加するデータ
		d->before=sd->bottom; //今回追加するデータの前のデータは末尾データ
		sd->bottom=d; //末尾データを今回追加したデータにする
	}
	sd->dno++; //バッファ数を増やす
	sd->inBucketSize+=size; //総バッファ数を増やす
	pthread_mutex_unlock(&sd->mutex);

	InfoLog("[info:%d]AppendSendData: %s %dbytes(Total=%lu:%lubytes)", deviceNo, InaddrToString(addr), size, sd->dno, sd->inBucketSize);
//	ViewSendData(ip2mac);

	return 0;
}

/*
 * IP2MAC_TIMEOUT_SECかIP2MAC_NG_TIMEOUT_SECで期限切れのip2macのバッファを捨てる
 */
int FreeSendData(IP2MAC *ip2mac){
	SEND_DATA	*sd=&ip2mac->sd;
	DATA_BUF	*ptr;
	int status;
//	char buf[80];

	//バッファがすでに空の場合終了
	if(sd->top==NULL){
		return 0;
	}

	//ip2macの送信待ちデータをロックする
	if((status=pthread_mutex_lock(&sd->mutex))!=0){
		InfoLog("[error%d]pthread_mutex_lock:%s", ip2mac->deviceNo, strerror(status));
		return -1;
	}

	//送信待ちデータのメモリを解放する
	for(ptr=sd->top; ptr!=NULL; ptr=ptr->next){
	//	InfoLog("[info:%d]FreeSendData:%s allsize:%lu", ip2mac->deviceNo, InaddrToString(ip2mac->addr), sd->inBucketSize);
		InfoLog("[info:%d]FreeSendData size:%lu", ip2mac->deviceNo, ptr->size);
		free(ptr->data);
	}

	//送信待ちデータを捨てる
	sd->top=sd->bottom=NULL;

	//ip2macの送信待ちデータのロックを解放する
	pthread_mutex_unlock(&sd->mutex);

	InfoLog("[info:%d]FreeSendData End:dst_ip(%s) allsize(%lu)", ip2mac->deviceNo, InaddrToString(ip2mac->addr), sd->inBucketSize);

	return 0;
}

int GetSendData(IP2MAC *ip2mac, int *size, u_char **data){
	SEND_DATA	*sd=&ip2mac->sd;
	DATA_BUF	*d;
	int status;
//	char buf[80];

	//送信データがなければ終了
	if(sd->top==NULL){
		return -1;
	}

	//送信データをロックする
	if((status=pthread_mutex_lock(&sd->mutex))!=0){
		InfoLog("[[error]]pthread_mutex_lock:%s", strerror(status));
		return -1;
	}
	d=sd->top; //一番最初のデータを格納する
	sd->top=d->next; //一番最初のデータを次のデータにする
	if(sd->top==NULL){ //次のデータがなければ
		sd->bottom=NULL; //もうデータは残ってないのでbottomもNULLにする
	}else{
		sd->top->before=NULL; //前のデータ、つまり今回取得したdはバッファからなくなるのでNULLにする
	}
	sd->dno--; //バッファ数を１つ減らす
	sd->inBucketSize-=d->size; //バッファの総サイズを今回取得したデータサイズ分減らす

	//送信データのロックを解放する
	pthread_mutex_unlock(&sd->mutex);

	*size=d->size;
	*data=d->data;

	free(d); //今回取得したデータの確保分メモリを解放する

	InfoLog("[[info:%d]]GetSendData: %s %dbytes", ip2mac->deviceNo, InaddrToString(ip2mac->addr), *size);

	return 0;
}
