#include "mylibpcap.h" /****
 * to analyze the packet captured 
 ****/

#define ETHER_ADDR_LEN  6  /* mac addr length */
#define ETHER_TYPE_LEN 2   /* type */
#define ETHER_CRC_LEN 4   /*CRC length*/ 
#define ETHER_HDR_LEN  ((ETHER_ADDR_LEN)*2 + (ETHER_TYPE_LEN))
#define ETHER_MIN_LEN 64
#define ETHER_MAX_LEN 1518
#define ETHER_IS_VALID_LEN(foo) \
	((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)    

struct ether_header {

	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct ether_addr {
	u_char octet[ETHER_ADDR_LEN];

};


#define ETHERTYPE_PUP  0x0200
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0800 
#define ETHERTYPE_REVARP 0x8035
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86dd
#define ETHERLOOPBACK  0x9000
#define ETHERTYPE_IPX 0x8137


typedef struct _EtherHdr {
	unsigned char ether_dst[6];
	unsigned char ether_src[6];
	unsigned short ether_type;
} EtherHdr;





void analysis_ethernet(u_char *user, const struct  pcap_pkthdr *h, u_char *p)
{	
	int length;
	int caplen;int ether_type;
	EtherHdr *ep;

	legth = h->len;
	caplen = h->caplen;
	printf("         Ethernet Header(%u.%06u)\n",
			(u_int32_t)h->ts.tv_sec,(u_int32_t)h->ts.tv_usec);

	if(caplen  < sizeof(EtherHdr)) {
		printf("Ethernet header too short!(%d bytes)\n",length);
		return ;
	}
	



	}


}

struct hook_and_sinker
{
	void (*hook) (packet_data*, void**);
	void **args;
	int proc_flags;
	bpf_u_int32 linktype;
}


void print_packet(packet_data* p, int what_to_show)
{
	struct ip* ip; 
	struct tcphdr* tcp;
	struct udphdr* udp;
	struct icmp* icmp;
#ifdef INET6
	struct icmp6_hdr* icmp6;
	struct ip6_hdr* ip6;
#endif
	if(what_to_print & PP_SHOW_BASICINFO) {
		printf("PACKET SIZE: %d",p->packet_len);
		if(p->packet_len != p->buffer_len)
			printf(",(BUFFER SIZE:%d)",p->buffer_len);
		printf("\n");
	}

	if(what_to_print &PP_SHOW_ETHERTYPE_LINKLAYER) {
		if(p->ether.ether_type == ETHERTYPE_ARP) {

		print_arp_header(&(p->data.arp));
		printf("---------------------------\n");
		return;
	}
	}

	if((p->link_type & GENERIC_LINK_OTHER) != GENERIC_LINK_IP
#ifdef INET6
			&&(p->link_type &GENERIC_LINK_OTHER)!= GENERIC_LINKS_IP6
#endif
	  )
		return;

	ip = &(p->data.ip.hdr);
	if(is_ip_packet(p))
		tcp = &(p->data.ip.body.tcphdr);
	if(is_ip_packet(p))
		udp = &(p->data.ip.body.udphdr);

	icmp = &(p->data.ip.body.icmp);
#ifdef INET6
	ip6 = &(p->data.ip6.hdr);

	if(is_ip6_packet(p)) {
		tcp = &(p->data.ip6.body.tcphdr);
		udp = &(p->data.ip6.body.udphdr);
		icmp6 = &(p->data.ip6.body.icmp6hdr);
	}
#endif

	if(what_to_print & PP_SHOW_IPHEADER) {
		if(is_ip_packet(p))
			print_ip_header(ip);

#ifdef INET6
		if(is_ip6_packet(p)) 
			print_ip6_header(ip6);
#endif
	}

	p->buffer_len -= sizeof(struct ip);
	switch (get_ip_proto (p)) {
		case IPPROTO_TCP:
			print_tcp_header(tcp,p->buffer_len,what_to_print);
			break;
		case IPPROTO_UDP:
			print_udp_header(udp,p->buffer_len,what_to_print);
			break;
		case IPPROTO_ICMP:
			print_icmp_header(icmp,p->buffer_len,what_to_print);
			break;
		#ifdef INET6
		case IPPROTO_ICMPV6:
			print_icmp6_header(icmp6,p->buffer_len,what_to_print);
			break;
#endif
		default:
			printf("UNKNOWN IP PROTOCOL! (0x%.4X)\n",get_ip_proto(p));
			break;
	}
}


	





void my_hook(packet_data *pd, void **args)
{
	print_packet(pd, what_to_show);
}




void process_pcap(u_char*, const struct pcap_pkthdr* , const u_char*);

/******************************************************************************
 * take tcp protocal as example:
 * if the ethenet frame's inital address is A, then
 * ip's  is A+14 ,'cause the length of the ethernet frame's header is 14, then
 * tcp's is A+14+20, the length of the ip's header is 20, then
 * data's is A+14+20+20 , the length of the tcp's header is 20 ,too.
 *
 * ****************************************************************************/

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	const struct sniff_ethernet* ethernet;//the header of ethernet
	const struct sniff_ip* ip ; //the header of ip
	const struct sniff_tcp* tcp; //the header of tcp

	int size_ethernet = sizeof(struct sniff_ethernet);//the size of ehternt
	int size_ip = sizeof(struct sniff_ip);//the size of header of ip
	int size_tcp = sizeof(struct sniff_tcp);//the size of the header of tcp

	char string[1024];
	char timestr[1024];
	char number[1024];
	char destip[1024];
	char ether_type_string[1024];

	GtkWidget* list;
	int ether_type;
	pcaketnumber = count;
	sprintf(packet_number_string, "%d",packetnumber);
	
	clear_all_variable(); //clear all the header_string_object

	analysis_ethernet(args, header, packet);//analyze the ethernet
	if(show_packet_conten == 1) 
		proc_pcap(args, header, packet);
	process_pacp(args, header, packet);
	if(savefile_yesno == 1) pcap_dump ((void*) dumper_filename, header,packet);
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + size_ethernet);
	tcp = (struct sniff_tcp*) (packet + size_ethernet + size_ip);

	ether_type = ntohs(ethernet->ether_type);
	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP:
			strcpy(ether_type_string,"IP"); break;
		#ifdef INET6
		case ETHERTYPE_IPV6:
			strcpy(ether_type_string,"IPV6"); break;

		#endif

		case ETHERTYPE_ARP:
			strcpy(ether_type_string, "ARP");
			gdk_thread_enter();
			add_list_to_clist1();
			gdk_threads_leave();
			break;
		case ETHERTYPE_REVARP:
			strcpy(ether_type_string,"REVARP"); break;
		case ETHERTYPE_IPX:
			printf("ipx \n");
			strcpy(ether_type_string, "IPX");
			break;
		case ETHERTYPE_AT:
			strcpy(ether_type_string, "AT");break;
		case ETHERTYPE_AARP:
			strcpy(ether_type_string, "AARP");
			break;
		default:
			break;
	}


	if(threadstop == 1)  pthread_exit(0);

	gdk_threads_enter();
	inserttime();
	gdk_threads_leave();
	getcurrenttime(timestr);
	strcpy(snifferpacket.time, timestr);
	sprintf(string,"Packet number %d has just been sniffed \n",count);

	strcpy(buffer, string);
	insert_text1("green");
	sprintf(string, "\tFrom:  %s:%d\n", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));

	if(strcmp(ether_type_string, "ARP") == 0) {
		sprintf(snifferpacket.source, "%s",arp_header_string_object.sorce_ip);
		sprintf(snifferpacket.sport, "%s", "");
	}

	else {
		sprintf(snifferpacket.source, "%s", inet_ntoa(ip->ip_src));
		sprintf(snifferpacket.sport,"%d", ntohs(tcp->th_sport));

	}

	strcpy(buffer, string);
	insert_text1("yellow");
	sprintf(string, "\tTo:   %s:%d\n", inet_ntoa(ip->ipdst), ntohs(tcp->th_dport));

	sprintf(destip, "%S", inet_ntoa(ip->ip_dst));
	if(strcmp(ether_type_string, "ARP") == 0) {
		sprintf(snifferpacket.destination, "%s", arp_header_string_object.destination_ip);
		sprintf(snifferpacket.dport, "%s","");
	}
	else {
		sprintf(snifferpacket.destination, "%s", inet_ntoa(ip->ip_dst));
		sprintf(snifferpacket.dport, "%d",ntohs(tcp->th_dport));
	}

	strcpy(buffer, string);
	insert_text1("cyan");
	gdk_threads_enter();
	counnt++; 

	if(use_database_yesno == 1) insert_sniffer_into_database();

	button_add_clicked();
	label = lookup_widget(window, "label");
	sprintf(number, "Packet Number: %d", packetnumber);
	gtk_label_set_text(GTK_LABEL(label), number);
	label = lookup_widget(window, "baojinglabel");
	if(strcmp(desip, "192.168.0.1") == 0) {
		gtk_label_set_text(GTK_LABEL(label),"destip is 192.168.0.1");
	}
	gdk_threads_leave();
	get_ip_variable();

	get_tcp_variable();
	get_udp_variable();
	get_icmp_variable();
	whole_parse_rules();
}


void process_pcap(u_char* user, const struct pcap_pkthdr* h, const u_char*p)
{
	struct hook_and sinker* hs;
	struct ether_header* ep;

	u_int length = h->caplen.x;
	u_char* packet;

	hs = (struct hook_and_sinker*) user;
	packet = (u_char*) p;//存放网络数据包内容

	ep = (struct ether_header*) p;
	pdata.link_type = 0;
	switch(hs->linktype) {
		case DLT_NULL:
			pdata.link_type = LINK_NONE;
			switch (*(int*) packet) {
				case AF_INET:
					pdata.link_type =LINK_NONE_IP;
					break;
				#ifdef INET6
				case AF_INET6:
					pdata.link_type = LINK_NONE_IP6;
					break;
				#endif
				default:break;

			}

			packet += sizeof(int);
			pdata.packet_len= h->len;
			break;

		case DLT_EN10MB:
			printf("DLT_EN10MB\n");
			packet += sizeof(struct ether_header);
			length -= sizeof(struct ether_header);
			bcopy(&(ep->ether_shost), &(pdata.ether.ether_shost)
					,sizeof(struct ether_addr);
			bcopy(&(ep->ether_dhost), &(pdata.ether.ether_dhost)
				,sizeof(struct ether_addr)));

			pdata.link_type = LINK_ETHERNET;
			switch (ntohs(ep->ether-type)) {
			case ETHERTYPE_IP:
				pdata.link_type = LINGK_ETHERNET_IP;
				break;
			#ifdef INET6
			case ETHERTYPE_IPV6:
				pdata.link_type = LINK_ETHERNET_IP6;
				break;
			#endif

			case ETHERTYPE_ARP:
				pdata.link_type = LINK_ETHERNET_ARP;
				break;

			case ETHERTYPE_REVARP:
				pdata.link_type = LINK_ETHERNET_REVEARP;
				break;

			case ETHERTYPE_IPX:
				pdata.link_type = LINK_ETHERNET_IPX;
				break;
			case ETHERTYPE_AT:
				pdata.link_type = LINK_ETHERNET_AT;
				break;

			case ETHERTYPE_AARP:
				pdata.link_type = LINK_ETHERNET_AARP;
				break;
			default:
				break;
			}
			
			pdata.ether.ether_type = ntohs(ep->ether_type);
			pdata.packet_len = h->len;
			if(!(hs->proc_flags & GET_TCPD_COUNT_LINKSIZE))
				pdata.pcaket_len -= ETHER_HDR_LEN;
			break;

		case DLT_PPP:
			pdata.link_type |= LINK_PPP;
			x = (packet[2] << 8)|packet[3];
			switch (x)
			{
				case 0x0021:  //ip
					pdata.link_type |= LINK_PPP_IP;
					break;
				case 0x8021: //ipcp
					pdata.link_type |= LINK_PPP_IPCP;
					break;
				#ifdef INET6
				case 0x0057: //ip6
					pdata.link_type |= LINK_PPP_IP6;
					break;
				case 0x8057: //ipcp6
					pdata.link_type |= LINK_PPP_IPCP6;
					break;
				#endif

				case 0x80fd: //ccp
					pdata.link_type |= LINKS_PPP_CCP;
					break;
				case 0xc021: //lcp
					pdata.link_type |= LINK_PPP_LCP;
					break;
				case 0xc023://pap
					pdata.link_type |= LINK_PPP_PAP;
					break;
				case 0xc223://chap
					pdata.link_type |= LINK_PPP_CHAP;
					break;
				default:
					pdata.link_type|= LINK_PPP_OTHER;
					break;
			}

			packet += PPP_HDRLEN;
			length -= PPP_HDRLEN;
			pdata.pcaket_len = h->len;
			if(!(hs->proc_flags & GET)TCPD_COUNT_LINKSIZE))
				pdata.packet_len -= PPP_HDRLEN;
			break;

		default:
#if DEBUG
			printf("Unknown link Type:%X\n", hs->linktype);
#endif
			break;
	}

	length =(length < PAK_SIZ) ? length : PAK_SIZ;

	bcopy ((void*)&(h->ts), &(pdata.timestamp), sizeof(struct timeval));
	bcopy (packet, &(pdata.data.raw),length);
	pdata.buffer_len = lenth;
	hs->hook (&pdata, hs->args);
}



	

			
			


