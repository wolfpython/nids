#ifndef _MYLIBPCAP_H
#define _MYLIBPCAP_H
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>


/************************************************
 按钮start的回调函数：
 参数：

 **************************************************/
void threads_click(GtkWidget* widget, gpointer data);

/** to dean with the real capturing packet stuff ****/
void* another_thread1(void* args);

/** to analyze the packet captured by the another_thread1 function ********/
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);




#endif

/*** EOF***/
