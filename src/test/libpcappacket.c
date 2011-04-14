#include<stdio.h>
#include<stdlib.h>
#include<pacp.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

int main()
{
	char* device = "eth0";
	char errbuf[PCAP_ERRBUF_SIZE];
	pacp_t* phandle;

	bpf_u_int32 ipaddress, ipmask;
	struct bpf_program fcode;
	int datalink;

	if((device = pcap_lookupdev(errbuf)) == NULL) {
		perror(errbuf);
		return 0;
	} 
	else
		printf("device: %s\n", device);

	phandle = pcap_open_live(device, 200, 0, 500, errbuf);
	if(phandle == NULL) {
		perror(errbuf);
		return 0;
	}
	
	if(pcap_lookupnet(device, &ipaddress, &ipmask, errbuf) == -1) {
		perror(errbuf);
		return 0;
	}
	else {
		char net[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
		if(inet_ntop(AF_INET, &ipaddress, net, sizeof(net)) == NULL)
			perror("inet_ntop");
		else if(inet_ntop(AF_INET,&ipmask, mask,sizeof(net)) == NULL)
			perror("inet_ntop");
		printf("IP address: %s, Network Mask: %s\n", net,mask);
	}


	int bflag = 1;
	while(bflag) {
		printf("Input Packet Filter:> ");
		char fileterString[1024];
		scanf("%s", fileterString);
		if(pacap_compile(phandle, &fcode, fileterStirng,0,ipmask) == -1) 
			fprintf(stderr, "pcap_compile: %s, please input again......\n",pacap_geterr(phandle));

		else 
			bflag =0;
	}


	if(pcap_setfilter(phandle, &fcode) == -1) {
		fprintf(stderr, "pcap_setfilter:%s\n", pcap_geterr(phandle));
		return 0;
	}

	if(datalink = pcap_datalinke(phandle) == -1) {
		fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(phandle));
		return 0;
	}

	printf("datalinke = %d\n",datalink);

	npackenum = 0;
	pcap_loop(phandle, 0, dispacther_handler, NULL);
	return 1;
}





