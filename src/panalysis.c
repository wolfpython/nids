#include "mylibpcap.h" /****
 * to analyze the packet captured 
 ****/

#pragma pack(1)
/*
 * ethernet data link layer
 * 
 */

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


typedef struct llc_header {
	u_int8_t dsap;
	u_int8_t ssap;

} llc_header_t;


void analysis_llc(const u_char *bp, int length)
{
	llc_header_t *llc;
	u_int8_t org_id[3];
	u_int16_t ethertype;
	u_int8_t control;
	llc = (llc_header_t *)bp;

	printf("LLC header \n");
	printf("DSAP: %d",llc->dsap);
	printf("SSAP:%d",llc->ssap);
	if(llc->dsap == 255 && llc->ssap == 255) {
		printf("analysis_ipx \n");
		return;
	}

	control = *(bp +2);
	prinf("Control: %d",control);
	gdk_threads_enter();
	add_list_to_clist6();

	gdk_threads_leave();
	if(llc->dsap == 240 && llc->ssap == 240) return;

	if(llc->dsap == 224 && llc->ssap == 224) {
		analysis_ipx(pkt );
		return;
	}
	if(llc->dsap == 170 && llc->ssap == 170) {
		org_id[0] =*(bp +3);

		org_id[1] =*(bp +4);
		org_id[1] =*(bp +5);

		ethertype = *(bp + 6);
		ethertype = ntohs(ethertype);
		printf("SNAP header");
		printf("Organization ID %d",org_id);
		printf("Protocol: %d",ethertype );

	}
	return;


}



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

	ep = (EtherHdr *)p;

	ether_type = ntohs(ep->ether_type);
	printf("Hardware source:%x:%x:%x:%x:%x:%x \n", *(p + 6),*(p +7),
			*(p +8),*(p + 9),*(p +10),*(p + 11));

	printf("Hardware destination:%x:%x:%x:%x:%x:%x \n", 
			*(p),*(p + 1),*(p +2),*(p +3),*(p + 4),*(p + 5));

	printf("Protocol type:             %xH \n",ether_type );


	printf("Length:                %d\n",length +4);
	packet_ptr = p;
	packet_end = p + caplen;

	p += sizeof(EtherHdr);
	if(ether_type <= ETHERMTU) {
		analysis_llc(p, length);
	} else {
		switch (ether_type) {
			case ETHERTYPE_IP:
				printf("ip in analysis_ehternet\n");
				analysis_ip(p,length);
				return;
			case ETHERTYPE_ARP:
			case ETHERTYPE_REVARP:
				analysis_arp(p,length);
				return;
			case ETHERTYPE_IPX:
				printf("ipx in analysis_ethernet \n");
				analysis_ipx(p,length - sizeof(EtherHdr));
				return;

			default:
				return;
		}
	}
}


/*
 * arp protocal analysis
 *
 */

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPOP_RREQUEST 3
#define ARPOP_RREPLY

typedef struct _ARPHdr {
	unsigned  short ar_hrd;
	unsigned short ar_pro;
	unsigned char ar_hln;
	unsigned char ar_plh;
	unsigned short ar_op;
}ARPHdr;

typedef struct _EtherARP {
	ARPHdr ea_hdr;
	unsigned char arp_sha[6];
	unsigned char arp_spa[4];
	unsigned char arp_tha[6];
	unsigned char arp_tpa[4];
}EtheARP;


struct my_arp_header_string {
	char hrd[1024];
	char pro[1024];
	char hln[1024];
	char plen[1024];
	char op[1023];
	char source_hardware[1024];
	char source_ip[1024];
	char destination_hardware[1024];
	char destination_ip[1024];
	char information[1023];
};

struct my_arp_header_string arp_header_string_object ;

void analysis_arp(u_char *bp, int length, int caplen) 
{
	EtherARP *ap;
	u_short pro,hrd, op;
	struct  in_addr spa,tpa;
	char *etheraddr_string(u_char *ep);
	printf("------------------ARP Header---------------\n");
	ap = (EtherARP *) bp;
	if(length < sizeof(EtherARP)) {
		printf("Truncated packet\n");
		return;`
	}
	
	hrd = ntohs(ap->ea_hdr.ar_hrd);
	pro = ntohs(ap->ea_hdr.ar_pro);
	op = ntohs(ap->ea_hdr.ar_op);
	printf("Hardware type:           %d\n",hrd );
	printf("Protocal:              %d\n",pro);
	printf("Operation:            %d\n",op);
	switch (op) {
		
		case ARPOP_REQUEST:
			printf("(ARP request)\n");
			break;
		case ARPOP_REPLY:
			printf("(ARP replay)\n");
			break;
		case ARPOP_RREQUEST:
			printf("(RARP request)\n");
			break;
		case ARPOP_RREPLY:
			printf("RARP replay )\n");
			break;
		default:
			printf("(unknown)\n");
			return;

	}



mcpy((void *)&spa, (void *)&ap->arp_spa,sizeof(struct in_addr)i);
mcpy((void *)&tpa, (void *)&ap->arp_tpa,sizof(struct in_addr));

printf("Sender Hardware:      %s\n",etheraddr_string(ap->arp_sha));
printf("Send IP:             %s\n",inet_ntoa(spa));

printf("Target Hardware:        %s\n",etheraddr_string(ap->arp_tha));
printf("Target IP:              %s\n",inet_ntoa(tpa));
}

void print_arp_header(struct arp_hdr *arp) {
	printf("ARP packet:\n");
	printf("\t hrd-%d pro=%d hln=%d plen = %d op = %d",
			htons(arp->ar_hrd ),
			htons(arp->ar_pro),
			arp->ar_hln ,
			htons(arp->ar_op));
	sprintf(arp_header_string_object.hrd,"%d",
			htons(arp->ar_hrd));		;
	sprintf(arp_header_string_object.pro,"%d",htons(apr->ar_pro));
	sprintf (arp_header_string_object.hln,"%d",htons(apr->ar_hln));
	sprintf(arp_header_string_object.plen,"%d",htons(apr->ar_plen));
	sprintf(arp_header_string_object.op,"%d",htons(apr->ar_op));

	if(use_database_yesno == 1) 
		insert_sniffer_into_database();

	pritnf("\n");
}


/* 
 *IP protocal
 * 
 */


typedef struct _IPHdr {
#if defined(WORDS_BIGENDIAN)
	u_int8_t ip_v:4, ip_hl:4;
#else
	u_int8_t ip_hl:4, ip_v:4;
#endif
	
	u_int8_t ip_tos;
	u_int8_t ip_len;
	u_int8_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_p;
	u_int16_t ip_csum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
}IPHdr;

#define ICMP_NEXT_HEADER 1
#define IP_NEXT_HEADER 4
#define TCP_NEXT_HEADER 6
#define UDP_NEXT_HEADER 17
#define GRE_NEXT_HEADER 47
#define ESP_NEXT_HEADER 50
#define AH_NEXT_HEADER 51

struct my_ip_header_string {
	char version[1024];
	char header_length[1024];
	char tos[1024];
	char total_length[1024];
	char id[1024];
	char off[1024];
	char ttl[1024];
	char protocol[1024];
	char checksum[1024];
	char source_ip[1024];
	char destination_ip[1024];
};

struct my_ip_header_string ip_header_string_object;

void analysis_ip(const u_char *bp, int length)
{
	IPHdr *ip, ip2;
	u_int hlen, len, off;
	u_char *cp = NULL;
	u_int frag_off;
	u_char tos;
	u_int16_t csum;
	u_int16_t my_csum;

	ip = (IPHdr *)bp;
	len = ntohs(ip->ip_len);
	csum = ntohs(ip->ip_csum);
	hlen = ip->ip_hl *4;

	printf("Version:           %d \n",ip->ip_v);
	printf("Header length:         %d\n",hlen);
	tos = ip->ip_tos;
	printf("Type of service:     %d\n",tos);
	printf("Total length:        %d\n",ntohs(ip->ip_len));
	printf("Identification #:         %d\n", ntohs(ip->ip_id));

	frag_off = ntohs(ip->ip_off);
	printf("Fragmentation offset: %d",(frag_off & 0x1fff) *8);

	frag_off &= 0xe000;
	printf("(U =%d,DF = %d,MF = %d)\n",
			(frag_off &0x8000)>> 15,
			(frag_off &0x4000)>>14,(frag_off &0x2000)>>13);
	printf("Time to live: %d\n",ip->ip_ttl);
	printf("Protocol: %d\n",ip->ip_p);

	printf("Header checksum: %d",csum);

	memcpy((void *) &ip2,(void *)ip,sizeof(IPHdr));
	ip2.ip_csum = 0;
	
	my_csum = htons(in_cksum((u_int16_t *)& ip2,sizeof(IPHdr)));

	if(my_csum !csum)
		printf("(Error: should be %d)",my_csum);
	printf("Source address %s\n",inet_ntoa(ip->ip_src));
	printf("Destination address %s\n",inet_ntoa(ip->ip_dst));

	len -= hlen;

	off = ntohs(ip->ip_off);
	if((off &0x1fff) == 0) {
		cp = (u_char *) ip +hlen ;
		switch (ip->ip_p) {
			case TCP_NEXT_HEADER:
				analysis_tcp(cp,len);
				break;
			case UDP_NEXT_HEADER:
				analysis_udp(cp,len);
				break;
			case ICMP_NEXT_HEADER:
				analysis_icmp(cp);
				break;
			default:
				break;

				
		}
	}

}

/* 
 *Tcp/ip Illustrated volume 2,chapter 8
 */ 
 
u_int16_t in_cksum(u_int16_t *addr, int len)
{
	int nleft = len;
	u_int16_t *w = addr;
	u_int32_t sum = 0;
	u_int16_t answer = 0;
	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	
	if(nleft == 1) {
		*(u_int8_t *)(&answer) = *(u_int8_t *)w;
		sum += answer;

	}

	sum = (sum >> 16) + (sum & 0xffff);

	sum += (sum >> 16);
	answer = ~sum;

	return(answer);
}


void print_ip_header(struct ip *ip)
{
	char indnt[64]= " ";
	struct protoent *ip_prot;
	printf(" IP HEADER:\n");

	ip_prot = getprotobynumber(ip->ip_p);
	if(ip_prot == NULL) {
		printf("Couldn't get Ip protocol\n");
		return;
	}

	printf("%sver = %d hlen = %d TOS = %d ID = 0x%.2x", indnt,
#ifdef _IP_VHL
			ip->ip_vhl >> 4,(ip->ip_vhl & 0x0f) << 2,
			
#else
			ip->ip_v,ip->ip_hl<<2,
#endif
			ip->ip_tos,htons(ip->ip_len),htons(ip->ip_id));
	sprintf(ip_header_string_object.header_length,"%d",
#ifdef _IP_VHL 
			ip->ip_vhl >>4,
#else
			ip->ip_hl <<2
#endif
	       );
	sprintf(ip_header_string_object.version,
			"%d",
#ifdef _IP_VHL
			(ip->ip_vhl &0x0f) <<2,
#else
			ip->ip_v
#endif
	       );

sprintf(ip_header_string_object.tos,"%d",ip->ip_tos);

sprintf(ip_header_string_object.total_length,"%d",htons(ip->ip_len));

sprintf(ip_header_string_object.id,"%d",htons(ip->ip_id));
printf("\n%sFRAG=0x%.2x TTL=%u Proto=%s cksum=0x%.2x\n",indnt ,
		htons(ip->ip_off),
		ip->ip_ttl,ip_prot->p_name,htons(ip->ip_sum));

sprintf(ip_header_string_object.off,"%d",htons(ip->ip_off));
sprintf(ip_header_string_object.ttl,"%u",ip->ip_ttl);
sprintf(ip_header_string_object.protocol,"%s",ip_prot->p_name);
sprintf(ip_header_string_object.checksum,0x%.2x,htons(ip->ip_sum));


printf("%s%s",indnt,inet_ntoa(ip->ip_src));
sprintf(ip_header_string_object.source_ip,"%s",inet_ntoa(ip->ip_src));
printf("-> %s\n",inet_ntoa(ip->ip_dst));
sprintf(ip_header_string_object.destination_ip,"%s",inet_ntoa(ip->ip_dst));

if(use_database_yesno ==1)
	insert_ip_into_database();

gdk_thread_enter();
add_list_to_clist2();

gdk_threads_leave();
}

void proc_pcap(u_char *user, const struct pcap_pkthdr *h,const u_char *p)
{
	u_int length = h->caplen, i,j,k, step;
	u_char *r, *s;
	char c;
	char content[1024];
	char content_str[1024];
	char content_string[1024];

	r = (u_char *)p;
	s = (u_char *)p;
	step = 22;
	printf("%u: %u.%.6u, caplen %u, len %u\n",
			count,
			(long unsigned int)h->ts.tv_sec,
			(long unsigned int)h->ts.tv_usec,h->caplen,h->len);
	sprintf(content, "%u: %u.%.6lu,caplen %u,len %u\n",
			count,
                        (long unsigned int)h->ts.tv_sec,
			(long unsigned int)h->ts.tv_usec,h->caplen,h->len);
	gdk_threads_enter();
	insert_text2(content);
	gdk_threads_leave();

	for(i = 0; i < length;) {
		sprintf(content, " ");
		gdk_threads_enter();
		insert_text2(content);
		gdk_threads_leave();
		for(j = 0; j < step && (j+1) < length;) {
			sprintf(content, "%.2x",*r++);
			gdk_thread_enter();
			insert_text2(content);
			gdk_threads_leave();
			j++;
			if((j+i) == length) {
				sprinft(content, " ");
				gdk_threads_enter();
				insert_text2(content);
				gdk_threads_leave();
				j++;
				break;
			}
			sprintf(content, "%.2x",*r++);
			gdk_threads_enter();
			insert_text2(content);
			gdk_threads_leave();
			j++;
		}
		for(k = j; k < step; k++,k++) {
			sprintf(content, " ");
			gdk_threads_enter();
			insert_text2(content);
			gdk_threads_leave();

		}
		sprintf(content, "           ");
		gdk_threads_enter();
		insert_text2(content);
		gdk_threads_leave();
		for(j = 0; j <step &&(j+i) < length; j++) {
			c = *p++;
			sprintf(content_string, "%c",char_conv(c));
			gdk_threads_enter();
			insert_text2(content_string);
			gdk_threads_leave();

		}
		sprintf(content, "\n");
		gdk_threads_enter();
		i += j;

	}
	sprintf(content, "\n");
	gdk_threads_enter();
	insert_text2(content);
		gdk_threads_leave();	
}













struct hook_and_sinker
{
	void (*hook) (packet_data*, void**);
	void **args;
	int proc_flags;
	bpf_u_int32 linktype;
};


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



	

			
			


