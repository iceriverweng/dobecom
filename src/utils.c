/*
utils.c - dobecom some func
by dixyes (dixyes@gmail.com)

*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "utils.h"


#ifdef _WIN32
void sleep(unsigned int seconds)
{
    clock_t goal = seconds*1000 + clock();
    while (goal > clock());
}
#endif // _WIN32
#ifdef _DEBUG
void printx(void*buf,uint16_t len)
{
    unsigned char* bufptr=buf;
    uint16_t ii;
    for(ii=0; ii<len; ii++)
    {
        printf("%02x ",*(bufptr+ii));
        if(!((ii+1)%8))
            printf("   ");
        if((ii+1!=len)&&!((ii+1)%16))
            printf("\n");
    }
    if(((ii+1)%16))
        printf("\n");
}

uint64_t rand_interval(uint64_t min, uint64_t max)
{
    uint64_t r;
    const uint64_t range = 1 + max - min;
    const uint64_t buckets = RAND_MAX / range;
    const uint64_t limit = buckets * range;

    do
    {
        r = rand();
    }
    while (r >= limit);

    return min + (r / buckets);
}
#endif // _DEBUG
void error(const char *msg)
{
    int errnum=errno;
    perror(msg);
    exit(errnum);
}
