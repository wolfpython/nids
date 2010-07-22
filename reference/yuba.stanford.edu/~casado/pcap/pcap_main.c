/**********************************************************************
* file:   pcap_main.c
* date:   Tue Jun 19 20:07:49 PDT 2001  
* Author: Martin Casado
* Last Modified:2001-Jun-23 12:55:45 PM
*
* Description: 
* main program to test different call back functions
* to pcap_loop();
*
* Compile with:
* gcc -Wall -pedantic pcap_main.c -lpcap (-o foo_err_something) 
*
* Usage:
* a.out (# of packets) "filter string"
*
**********************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 

/*
 * workhorse function
 */ 

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
}


int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;

    /* Options must be passed in as a string because I am lazy */
    if(argc < 2){ 
        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
        return 0;
    }

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }


    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }

    /* ... and loop */ 
    pcap_loop(descr,atoi(argv[1]),my_callback,args);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
