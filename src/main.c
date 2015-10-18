/*
main.c-dobecom main
by dixyes (dixyes@gmail.com)
progress socket and other things
*/
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h> //linux only
#endif // _WIN32

#include "version.h"
#include "dobepkt.h"
#include "dobecom.h"
#include "utils.h"

time_t bftime;
int sock;
int16_t i;
pthread_t thread[2];

struct dobeinfo info;
struct workstate state;

int init_socket(struct dobeinfo *);
void usage(void);
unsigned int usend(int,uint16_t);
int urecv(int);
void *udial(void *);
void *ukplv(void *);
void *ulisten(void *);
void *ulogout(void *);
void sigproc (int);

int main(int argc,char *argv[])
{
#ifdef _DEBUG
    for(int dei1=0; dei1<argc; dei1++)
        printf("%s ",argv[dei1]);
    printf("\n");
#endif // _DEBUG

    int opt=0;
    struct sockaddr_in tmpaddr;

    memset((char *)&info, 0, sizeof(info));
    memset((char *)&state, 0, sizeof(state));


    printf("Dobecom - redesigned dogecom for complex envir0nment build %ld\n",BUILDS_COUNT);

//arguscan:
    opterr = 0;
    while ((opt = getopt(argc, argv, "m:u:p:s:i:l:n:N:t:d:c:S:ABDHPTXfhv")) != -1)
    {
        switch (opt)
        {
        case 'm':
            info.mac=strtoll(optarg,NULL, 16);
            break;
        case 'u':
            strcpy(info.username,optarg);
            if(strlen(info.username)>MAX_USRNM)
            {
                fprintf(stderr,"Username is too long\n");
                exit(E2BIG);
            }
            break;
        case 'p':
            strcpy(info.password,optarg);
            if(strlen(info.password)>MAX_PWD)
            {
                fprintf(stderr,"Password is too long\n");
                exit(E2BIG);
            }
            break;
        case 's':
            if(inet_aton(optarg,&state.serveraddr.sin_addr)==0)
            {
                fprintf(stderr,"Wrong server IP\n");
                exit(EINVAL);
            }
            break;
        case 'i':
            if(inet_aton(optarg,&state.localaddr.sin_addr)==0)
            {
                fprintf(stderr,"Wrong local binding IP\n");
                exit(EINVAL);
            }
            break;
        case 'l':
            if(info.lcount<4)
            {
                if(inet_aton(optarg,&tmpaddr.sin_addr)==0)
                {
                    fprintf(stderr,"Wrong local dialing IP %s\n",optarg);
                    exit(EINVAL);
                }
                memcpy(info.localips[info.lcount++],&tmpaddr.sin_addr.s_addr,4);
            }
            else
                fprintf(stderr,"Extra local dialing IP %s ,ignore it.\n",optarg);
            break;
        case 'N':
            if(inet_aton(optarg,&tmpaddr.sin_addr)==0)
            {
                fprintf(stderr,"Wrong pri DNS IP %s\n",optarg);
            }
            memcpy(info.pdnsip,&tmpaddr.sin_addr.s_addr,4);
            break;
        case 'd':
            if(inet_aton(optarg,&tmpaddr.sin_addr)==0)
            {
                fprintf(stderr,"Wrong DHCP server IP %s\n",optarg);
            }
            memcpy(info.dhcpip,&tmpaddr.sin_addr.s_addr,4);
            break;
        case 'n':
            if(inet_aton(optarg,&tmpaddr.sin_addr)==0)
            {
                fprintf(stderr,"Wrong secondary DNS IP %s\n",optarg);
            }
            memcpy(info.sdnsip,&tmpaddr.sin_addr.s_addr,4);
            break;
        case 'c':
            strcpy(info.dobever,optarg);
            break;
        case 'S':
            strcpy(info.sstring,optarg);
            break;
        case 'A':
            state.autologout=true;
            break;
        case 'B':
            state.broadcast=true;
            break;
        case 'D'://norm dhcp dial
        case 'C'://change pass
        case 'X'://8021x dial
        case 'P'://pppoe dial
        case 'L'://only login
        case 'h':
        case 'H'://help
            state.mode=opt;
            break;
        case 'v':
            state.verbose = true;
            break;
        }
    }
//todo:argu check
    if (opterr)
    {
        usage();
        exit(opterr);
    }
    

    switch(state.mode)
    {
    case 'D':
    case 'L':
        sock=init_socket(&info);
        signal(SIGTERM,sigproc);
        signal(SIGINT,sigproc);
#if defined(__linux__) || defined (__MACH__)
        if(pthread_create(&thread[0], NULL, ulisten, NULL) != 0)
            error("pthread_create");
        while(true)
        {
        if(pthread_create(&thread[1], NULL, udial, NULL) != 0)
            error("pthread_create");
        if(thread[1] !=0)
        {
            pthread_join(thread[1],NULL);
            printf("dial done\n");
        }
        if(pthread_create(&thread[1], NULL, ukplv, NULL) != 0)
            error("pthread_create");
        if(thread[1] !=0)
        {
            pthread_join(thread[1],NULL);
            printf("kplv timeout,redial\n");
        }
        }
#endif // __linux__

    case 'h':
    case 'H':
        usage();
        break;
    }

    return 0;
}

void sigproc (int cause)
{
    if(cause==SIGINT)
        fprintf(stderr,"keyboard int\n");
    if(state.loggedin)
    {
        if(pthread_create(&thread[1], NULL, ulogout, NULL) != 0)
            error("pthread_create");
    }


#ifdef _WIN32
        WSACleanup();
#endif // _WIN32
    bftime=time(NULL);
    while((bftime>time(NULL)-WAIT_TIME)&&(state.loggedin));
    state.exiting=true;
    close(sock);
    exit(cause);
}

int init_socket(struct dobeinfo *info)
{
    //struct timeval tv;

#ifdef _WIN32
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2, 2), &wsaData))
        error("WSAStartup");
#endif
    if ((sock=socket(AF_INET, SOCK_DGRAM,0)) < 0)
        error("socket");
    state.localaddr.sin_family=AF_INET;
    state.serveraddr.sin_family=AF_INET;
    state.localaddr.sin_port=htons(DOBE_CLI_PORT);
    state.serveraddr.sin_port=htons(DOBE_SVR_PORT);
    if(state.localaddr.sin_addr.s_addr==0)
        state.localaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    if(state.serveraddr.sin_addr.s_addr==0)
        inet_aton(D_SVR_IP,&state.serveraddr.sin_addr);
    if(bind(sock,(struct sockaddr *)&(state.localaddr),sizeof(struct sockaddr_in))<0)
        error("binding");

    return sock;
}

void *ulogout(void * ptr)
{
    while((!state.salt_got)&&(state.challegecount<MAX_CHA_TRY))
    {
        i=usend(sock,T_CHAPKT);
        bftime=time(NULL);
        if(state.verbose)
            printf("%d bytes sent\n",i);
        while((bftime>time(NULL)-WAIT_TIME)&&(!state.salt_got));
        if(state.salt_got)
            break;
    }
    if(state.challegecount>=MAX_CHA_TRY)
    {
        fprintf(stderr,"cha fail\n");
        exit(-1);
    }
    if(state.salt_got)
    {
        i=usend(sock,T_LGOPKT);
    if(state.verbose)
        printf("logout sent\n");
    }
    pthread_exit(NULL);
}

void *ulisten(void * ptr)
{
    while(!state.exiting)
        if((i=urecv(sock))>0)
        {
            if(state.verbose)
                    printf("%d bytes recv\n",i);
        }
        else
            fprintf(stderr,"error receiving\n");
    pthread_exit(NULL);
}

void *udial(void * ptr)
{
    while((!state.salt_got)&&(state.challegecount<MAX_CHA_TRY))
        {
        i=usend(sock,T_CHAPKT);
        bftime=time(NULL);
        if(state.verbose)
            printf("%d bytes sent\n",i);
        while((bftime>time(NULL)-WAIT_TIME)&&(!state.salt_got));
        if(state.salt_got)
            break;
        }
    if(state.challegecount>=MAX_CHA_TRY)
    {
        fprintf(stderr,"cha fail\n");
        exit(-1);
    }
    if(state.salt_got)
    {
        i=usend(sock,T_LGIPKT);
        if(state.verbose)
            printf("%d bytes sent\n",i);
        while((bftime>time(NULL)-WAIT_TIME)&&(!state.loggedin));
        if(state.loggedin)
            state.salt_got=false;
        else
        {
            fprintf(stderr,"login fail!\n");
            exit(-1);
        }
    }
    pthread_exit(NULL);
}
void *ukplv(void * ptr)
{
    while(state.loggedin)
        {
            i=usend(sock,T_KALPKT);
            if(state.verbose)
                printf("%d bytes sent\n",i);
            bftime=time(NULL);
            while((bftime>time(NULL)-WAIT_TIME)&&(!state.kalsuc));
            if(state.kalsuc)
            {
                state.kalsuc=false;
                int protect=0;
                while((state.mcstate<4)&&(protect++<5))
                {
                    state.miscsuc=false;
                    i=usend(sock,T_MSCPKT);
                    if(state.verbose)
                        printf("%d bytes sent\n",i);
                    bftime=time(NULL);
                    while((bftime>time(NULL)-WAIT_TIME)&&(!state.miscsuc));

                }
                state.kalsuc=false;
                if(state.mcstate<4)
                {
                    state.loggedin=false;
                    pthread_exit(NULL);
                }
                printf("misc exchange sucess\n");
            }
            else
            {
                state.loggedin=false;
                pthread_exit(NULL);
            }

            sleep(20);
        }
    pthread_exit(NULL);
}

unsigned int usend(int socket,uint16_t pkttype)
{
    char *buf;
    int16_t i=0;

    switch (pkttype)
    {
    case T_CHAPKT:
        buf=challegepkt();
        i=sizeof(struct dobechapkt);
        break;
    case T_LGIPKT:
        buf=loginpkt();
        i=sizeof(struct dobelgipkt);
        break;
    case T_KALPKT:
        buf=heartpkt();
        i=sizeof(struct dobekalpkt);
        break;
    case T_LGOPKT:
        buf=logoutpkt();
        i=sizeof(struct dobelgopkt);
        break;
    case T_MSCPKT:
        buf=miscpkt();
        i=DOBEMISC_LENGTH;
        break;
    default:
        fprintf(stderr,"usend:Unknown packet type 0x%04x!\n",pkttype);
        exit(errno);
    }
#ifdef _DEBUG
    printx((unsigned char *)buf,i);//fake
#endif // _DEBUG
    i=sendto(socket, buf,i, 0, (struct sockaddr *)&state.serveraddr,sizeof(struct sockaddr_in));
    free(buf);
    if(i<=0)
        error("usend");
    return i;
}

int urecv(int socket)
{
    void *buf=malloc(MAX_RECV_PKT);
    int16_t i=0;
    i=recvfrom(socket, (unsigned char*)buf,MAX_RECV_PKT, 0, NULL, NULL);
    switch (*(unsigned char *)buf)
    {
    case T_CHRPKT:
        if(i>=sizeof(struct dobechrpkt))
        {
            struct dobechrpkt *chrptr=buf;
            memcpy(state.salt,chrptr->salt,4);
            state.salt_got=true;
#ifdef _DEBUG
            printf("salt is ");
            printx(state.salt,4);
#endif // _DEBUG
        }
        else
            fprintf(stderr,"Invaild cha respond pkt lngth!\n");
        break;
    case T_SUCPKT:
        if(i==DOBELGISUC_LENGTH)
        {
            struct dobesucpkt *sucptr=buf;
            memcpy(state.auth,sucptr->auth,16);
            //get info from ptr
            state.loggedin=true;
        }
        else if(i==DOBELGOSUC_LENGTH)
        {
            printf("logged out\n");
            state.loggedin=false;
        }
        else
            fprintf(stderr,"Invaild sucess pkt lngth %d!\n",i);
        break;
    case T_FALPKT:
        fprintf(stderr,"login fail pkt");
        state.loggedin=false;
        switch(*(uint8_t*)(buf+4))
        {
        case 0x03:
            fprintf(stderr," - wrong combination\n");
            break;
        case 0x16:
            fprintf(stderr," - wrong mac or ip\n");
            break;
        case 0x01:
            fprintf(stderr," - account already loged in using\n");
            break;
        default:
            fprintf(stderr," - unknown 0x%02X\n",*(uint8_t*)(buf+4));
            break;
        }
        break;
    case T_MSGPKT:
        //todo :show
        printf("msgpkt:\n");
        break;
    case T_MSCPKT:
        switch(ntohs(((struct dobemscpkt *)buf)->type))
        {
        case MTS_FILE:
            if(state.verbose)
                printf("got file ,ignore it\n");
        case MTS_ROK:
            state.mcstate=0;
            state.miscsuc=true;
            state.kalsuc=true;
            state.time=((struct dobemscpkt *)buf)->time;
            if(state.verbose)
            printf("got keep alive resp\n");
            break;
        case MTS_2800:
            state.mcstate=((struct dobemscpkt *)buf)->mctype;
            state.time=((struct dobemscpkt *)buf)->time;
            memcpy(state.ukn1,&((struct dobemscpkt *)buf)->uknown1,2);
            memcpy(state.ukn2,&((struct dobemscpkt *)buf)->mm,4);
            state.miscsuc=true;
            if(state.verbose)
            printf("got common misc\n");
            break;
        default:
            fprintf(stderr,"urecv:Unknown misc pkttype: %04X\n",ntohs(((struct dobemscpkt *)buf)->type));
        }

        break;
    default:
        fprintf(stderr,"urecv:Unknown packet type 0x%02x!,ignore it\n",*(char *)buf);
    }
#ifdef _DEBUG
        printx(buf,i);
#endif // _DEBUG
    free(buf);
    return i;
}

void usage()
{
    printf("Usage here\n");
    exit(0);
}
