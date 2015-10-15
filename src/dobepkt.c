/*
dobepkt.c - dobecom packet builder
by dixyes (dixyes@gmail.com)

*/
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/utsname.h>
#endif
#ifdef _DEBUG
#include <stdio.h>
#endif // _DEBUG

#include "dobecom.h"
#include "dobepkt.h"
#include "md5.h"
#include "utils.h"

#define HASH_TEMP_SIZE 128;

struct workstate state;
struct dobeinfo info;

void *challegepkt(void)
{
    struct dobechapkt *buf=malloc(sizeof(struct dobechapkt));
    buf->head=0x01;
    buf->try_times=(uint8_t)(1+state.challegecount++);
    buf->time=(uint16_t)htons(time(NULL));
    state.time=buf->time;
    buf->fixed_ver=0x0a;
    memset(buf->zeros,0,15*sizeof(uint8_t));
    return buf;
}
void *loginpkt(void)
{
    struct dobelgipkt *buf=(struct dobelgipkt *)malloc(sizeof(struct dobelgipkt));
    void *tmp_buf=(void *)malloc(6+strlen(info.password)); //generate hash tmp
    uint64_t *int64ptr;

    memset(buf,0,sizeof(struct dobelgipkt));

    /*build pkt*/
    buf->head=0x03; //head 1
    memcpy(buf->type,"\x01\x00",2);   //type 3
    buf->usr_lth=strlen(info.username)+20;    //usrnamelth 4
    memcpy(tmp_buf,"\x03\x01",2*sizeof(char));
    memcpy(tmp_buf+2,state.salt,4*sizeof(char));
    memcpy(tmp_buf+5,info.password,strlen(info.password)*sizeof(char));
    MD5(tmp_buf,6+strlen(info.password),buf->md5a);//make hasha into lgi pkt 20
    memcpy(state.md5a,buf->md5a,16);
    memcpy(buf->username,info.username,strlen(info.username)*sizeof(char));   //56
    memcpy(buf->fixed1,"\x20\x04",2);    //2004,unknown 58
    memcpy(buf->md5x,buf->md5a,6);  //md5x:md5a xor mac 64
    int64ptr=(uint64_t *)&buf->md5b-1;
    *int64ptr^=htonll(info.mac&0x0000FFFFFFFFFFFF);
    tmp_buf=realloc(tmp_buf,9+strlen(info.password));
    *(char *)tmp_buf='\x01';
    memcpy(tmp_buf+1,info.password,strlen(info.password)*sizeof(char));
    memcpy(tmp_buf+1+strlen(info.password),state.salt,4*sizeof(char));
    memset(tmp_buf+5+strlen(info.password),0,4*sizeof(char));
    MD5(tmp_buf,9+strlen(info.password),buf->md5b);//make hashb into lgi pkt 80
    buf->ipcount=info.lcount;  //local ip count 81
    memcpy(buf->localips,info.localips,16);//localip 97
    memcpy(buf->md5c,"\x14\x00\x07\x0b",4);
    MD5((uint8_t *)buf,101,buf->md5c); //md5c 105
    buf->ipdobe=0x01;   //ipdoge 106
    memset(buf->zeros1,0,4);    //zerosx4 110
    if(gethostname((char*)buf->hostname,32)!=0) //hostname 142
            memcpy(buf->hostname,D_HOSTNM,strlen(D_HOSTNM));
    memcpy(buf->pri_dns,info.pdnsip,12);
    //sys version - how can you use win style ver like 6.3.8888 to describe linux?

#ifdef _WIN32
        OSVERSIONINFO osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if(GetVersionEx(&osvi)==0)
            error("GetVersionEx");
        memcpy(buf->os_major,&osvi.dwMajorVersion,2);
        memcpy(buf->os_minor,&osvi.dwMinorVersion,2);
        memcpy(buf->os_build,&osvi.dwBuildNumber,2);
        memcpy(buf->os_uknown,"\x02",1);
#else
    struct utsname una;
    char * token;
    uint32_t * tmp=calloc(4,sizeof(uint8_t));
        if(uname((struct utsname *)&una)!=0)
            memcpy(buf->os_major,"\x06\0\0\0\x06\0\0\0\0\0\x01\0\x02",13);
        else
        {
            token=strtok(una.release,".-");
            if(token!='\0')
                *tmp=strtol(token,NULL,10);
            memcpy(buf->os_major,tmp,4);
            *tmp=0;
            token=strtok(NULL,".-");
            if(token!='\0')
                *tmp=strtol(token,NULL,10);
            memcpy(buf->os_minor,tmp,4);
            *tmp=0;
            token=strtok(NULL,".-");
            if(token!='\0')
                *tmp=strtol(token,NULL,10);
            memcpy(buf->os_build,tmp,4);
            *buf->os_uknown=0x02;
        }
    free(tmp);
#endif // _WIN32
    if(strlen(info.dobever)>0)
        strcpy((char *)buf->dobever,info.dobever);
    else
        strcpy((char *)buf->dobever,D_DOBEVERSIION);
    if(strlen(info.sstring)>0)
        strcpy((char *)buf->sstring,info.sstring);
    else
        strcpy((char *)buf->sstring,D_SSTRING);
    memcpy(buf->fixed3,"\x0a\x00",2);
    memcpy(buf->fixed4,"\x02\x0c",2);
    memcpy(buf->rand,buf->md5x,4);
    int64ptr=(uint64_t *)&buf->mac;
    *int64ptr=htonll(info.mac&0x0000FFFFFFFFFFFF);
    buf->auto_lgo=state.autologout;
    buf->bcastmode=state.broadcast;

    free(tmp_buf);//free buf
    return buf;
}
void *logoutpkt(void)
{
    struct dobelgopkt *buf=malloc(sizeof(struct dobelgopkt));
    return buf;
}
void *heartpkt(void)
{
    struct dobekalpkt *buf=malloc(sizeof(struct dobekalpkt));

    buf->head=0xff;
    memcpy(buf->md5a,state.md5a,16);//make hasha into pkt
    memcpy(buf->auth,state.auth,16);
    buf->time=state.time;

    return buf;
}
void *miscpkt(void)
{
    struct dobemscpkt *buf=malloc(DOBEMISC_LENGTH*sizeof(char));

    memset(buf,0,DOBEMISC_LENGTH*sizeof(char));

    buf->head=0x07;
    buf->initiative=0x01;
    buf->type=htons(MTS_2800);
    buf->zerob=0x0b;
    buf->mctype=state.mcstate+1;
    buf->time=state.time;
    memcpy(buf->uknown1,"\xd8\x02",2);
    buf->uknown2=rand();
    memcpy(buf->mm,state.ukn2,4);

    return buf;
}
