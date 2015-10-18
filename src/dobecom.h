/*
dobecom.h - dobecom header
by dixyes (dixyes@gmail.com)

*/
#ifndef _DOBE_CONST
#define _DOBE_CONST

#define DOBE_SVR_PORT 61440
#define DOBE_CLI_PORT 61440
#define WAIT_TIME 5
#define MAX_USRNM 36
#define MAX_PWD 64
#define MAX_CHA_TRY 10
#define MAX_RECV_PKT 512

#define D_DOBEVERSIION "8089D"//CUST uses none
#define D_SSTRING "a4e112f92be60a607d249a962dc79ce96f74ee64"//CUST String
#define D_SVR_IP "192.168.254.3"
#define D_DNS_IP "210.47.0.1"
#define D_SDNS_IP "202.98.0.68"
#define D_DHCP_IP "192.168.233.1"
#define D_HOSTNM "PC"


#endif // _DOBE_CONST

#ifndef _DOBE_STRUCT
#define _DOBE_STRUCT

#include <stdbool.h>
struct dobeinfo
{
    char username[MAX_USRNM];
    char password[MAX_PWD];
    uint64_t mac;
    uint8_t lcount;
    uint8_t localips[4][4];
    uint8_t pdnsip[4];
    uint8_t dhcpip[4];
    uint8_t sdnsip[4];
    char dobever[16];
    char sstring[40];
};

struct workstate
{
    uint8_t mode;
    uint8_t challegecount;
    bool sock_inited;
    bool salt_got;
    uint8_t salt[4];
    uint8_t auth[16];
    uint8_t md5a[16];
    uint8_t ukn1[2];
    uint8_t ukn2[4];
    uint8_t mcstate;
    uint16_t time;
    bool exiting;
    bool miscsuc;
    bool loggedin;
    bool kalsuc;
    bool verbose;
    bool autologout;
    bool broadcast;
    struct sockaddr_in localaddr;
    struct sockaddr_in serveraddr;
};

#endif // _DOBE_STRUCT
