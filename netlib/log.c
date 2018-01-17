#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "main.h"
#include "log.h"

void ErrorLog(char *msg){
	FILE *fp;
	char date[64];
	time_t t=time(NULL);

	fp = fopen(LOG_FILE,"a");
	strftime(date, sizeof(date), "%Y/%m/%d %a %H:%M:%S", localtime(&t));
	fprintf(fp,"%s[error]%s: %s\n",date,msg,strerror(errno));
	fclose(fp);
}

void InfoLog(char *fmt, ...){
	FILE *fp;
	char date[64];
	time_t t=time(NULL);
	va_list args;

	fp = fopen(LOG_FILE,"a");
	strftime(date, sizeof(date), "%Y/%m/%d %a %H:%M:%S", localtime(&t));
	fprintf(fp,"%s[info][pid:%d]",date,getpid());

	va_start(args,fmt);
	vfprintf(fp,fmt,args);
	va_end(args);

	fprintf(fp,"\n");

	fclose(fp);
}
