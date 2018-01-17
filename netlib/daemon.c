#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#include "main.h"
#include "log.h"
#include "daemon.h"

static void Reaper();
static void MakePidFile();
static void Daemonize();

static void Reaper(){
	int status;
	int chld_pid;
	chld_pid = wait(&status);
	InfoLog("reaper:chldpid=%d,status=%d",chld_pid,status);
}

static void MakePidFile(){
	FILE *fp;

	fp = fopen(PID_FILE,"w");
	fprintf(fp, "%d", getpid());
	fclose(fp);
}

static void Daemonize(){
	int pid;

	pid = fork();
	if(pid == -1){
		exit(1);
	}else if(pid > 0){
		//親プロセスの終了
		_exit(0);
	}

	//セッションリーダとなり制御端末を持たない状態にする
	if(setsid() < 0){
		exit(1);
	}

	close(0); //STDIN
	close(1); //STDOUT
	close(2); //STDERR

	MakePidFile();
	signal(SIGCHLD, (void *)Reaper);
}

void StartServer(){
	FILE *fp;

	fp = fopen(PID_FILE,"r");
	if(fp != NULL){
		printf("alerady running\n");
		exit(EXIT_FAILURE);
	}
	Daemonize();
	StartService();
}

void StopServer(){
	FILE *fp;
	int pid;

	fp = fopen(PID_FILE,"r");
	if(fp == NULL){
		printf("not run process\n");
		exit(EXIT_FAILURE);
	}else{
		StopService();
		fscanf(fp,"%d",&pid);
		//killだと接続中の子プロセスが残るためkillpgで一括に殺す
		killpg(pid,SIGINT);
		unlink(PID_FILE);
	}
}
