#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include "mylibpcap.h"
/************************************************
 按钮start的回调函数：
 参数：

 **************************************************/
void threads_click(GtkWidget* widget, gpointer data)
{
	pthread_t another , another1;// 线程句柄
	if (sniffer_active == 1 ) return ;//判断是否运行,1否
	
	threadstop = 0;
	count = 1;
	clear_all(NULL,NULL); //清除界面所有内容

	read_rules_from_file("rules");//从规则库中读取规则
	read_statement_from_rules();//把规则解析

	pthread_create(&another, NULL, another_thread, NULL); //创建一个线程，another_hread为其回调函数
	pthread_create(&another1,NULL, another_thread1, NULL); //创建两外一个线程，another_thread1()为回调函数

}


/********************************************************
 回调函数anther_thread1
 *******************************************************/

void *another_thread(void* args)

	char* dev; //网络设备
	char errbuf[PCAP_ERRBUF_SIZE]; //出错信息
	pcap_t* descr; //句柄
	struct bpf_program fp; //编译过的过滤规则
	bpf_u_int32 maskp; //子网掩码
	bpf_u_int32 netp; //ip 地址

	char filter_app[1024] = ""; //过滤规则
	char string[1024];
	struct hook_and_sinker hs;

	get_tcp_flags = GET_TCPD_COUNT_LINKSIZE;
	hs.hook = my_hook;

	hs.proc_flags = get_tcp_flags;
	what_to_show = PP_SHOW_IPHEADER | PP+SHOW_BASICINFO | PP_SHOW_LINKLAYER|PP_SHOW_PACKETCONTENT|PP_SHOW_TCPHEADER|PP_SHOW_UDPHEADER|PP_SHOW_ICMPHEADER;
	sniffer_active = 1;

	dev = (char*) malloc(sizeof(char)*1024);
	strcpy(dev, device_total);//网络设备
	strcpy(filter_app, filter_total);//过滤规则

	pcap_lookupnet(dev, &netp, &maskp, errbuf);
	strcpy(buffer, "");
	sprintf(string, "Device:[%s]\n",dev);
	strcpy(buffer, string);
	sprintf(string, "Num of packets:[%d] \n", sniffer_number);
	strcat(buffer, string);
	sprintf(string, "Filter app:[%s] \n", filter_app);
	strcat(buffer, string);
	insert_text1("gree");
	descr = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

	if(descr == NULL) {
		printf("pcap_open_live():%s\n",errbuf);
		exit(1);
	}

	if( pcap_compile(descr, &fp, filter_app, 0, netp) == -1) {
		printf("pcap_compile borken\n");
		exit(1);
	}

	if(pcap_setfilter(descr, &fp) == 1) {
		printf("pcap_setfilter broken\n");
		exit(1);
	}


	hs.linktype = pcap_datalink(descr);
	dumper_filename = pcap_dump_open(descr, savefile_string);
	if(dumper_filename == NULL) printf("dumper_filename err\n");

	pcap_loop(descr, sniffer_number, got_packet, (u_char*) &hs);
	//回调函数got_packet, 用来分析数据包
	

	pcap_close(descr);// 关闭会话
	pcap_dump_close(dumper_filename);//关闭文件

	sprintf(string, "Done sniffing\n");
	strcpy(buffer, string);
	insert_text1("purple");
	pthread_exit(0);
}




	




