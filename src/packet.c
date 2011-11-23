#include "goblin.h"


u_short header_chksum(u_short *ptr, int nbytes)
{
  unsigned long sum;
  u_short oddbyte;

  u_short answer;

  sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }

  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);
  answer = ~sum;

  return answer;  
}

void print_ipaddr(struct in_addr *ip_addr, char *ip_buf){
  u_char *ip_str;
  ip_str = (u_char *)&(*ip_addr);
  sprintf(ip_buf,"%d.%d.%d.%d",ip_str[0],ip_str[1],ip_str[2],ip_str[3]);
}

void send_packet(struct ip cap_iph, struct tcphdr cap_tcph){
  char packet[ETHER_MAX_LEN];
  char checksum_data[ETHER_MAX_LEN];
  struct ip *iph;
  struct tcphdr *tcph;
  struct tcphdr *tcp_ck;
  struct sockaddr_in sa;
  struct quasi_header *qh;
  socklen_t sa_len;
  unsigned long src_addr, dst_addr;
 
  unsigned long len;
  char buf[100];

  unsigned long tmp_seq;

  memset((void *)&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa_len = sizeof(sa);

  switch(cap_tcph.th_flags){
  case TH_SYN:
    sa.sin_port = cap_tcph.th_sport;
    sa.sin_addr = cap_iph.ip_src;
    sum_syn++;
    break;
  case TH_ACK:
    sa.sin_port = cap_tcph.th_dport;
    sa.sin_addr = cap_iph.ip_dst;
    sum_ack++;
    break;
  }


  len = sizeof(struct ip) + sizeof(struct tcphdr);


  iph = (struct ip *) packet;
  tcph = (struct tcphdr *)(packet + sizeof(struct ip));

  iph->ip_v = 4;
  iph->ip_hl = 5;
  iph->ip_tos = 0x10;
  iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
  iph->ip_off = 0;
  iph->ip_ttl = 16;
  iph->ip_p = IPPROTO_TCP;
  iph->ip_sum = 0;


  switch(cap_tcph.th_flags){
  case TH_SYN:
    iph->ip_src = cap_iph.ip_dst;
    iph->ip_dst = cap_iph.ip_src;
    tcph->th_sport = cap_tcph.th_dport;              
    tcph->th_dport = cap_tcph.th_sport;

    tmp_seq = ntohl(cap_tcph.th_seq);
    tmp_seq++;
    tcph->th_ack = htonl(tmp_seq);
    tcph->th_seq = 0;

    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_win = htons((u_short) 0);

    break;
  case TH_ACK:
    iph->ip_src = cap_iph.ip_src;
    iph->ip_dst = cap_iph.ip_dst;
    tcph->th_sport = cap_tcph.th_sport;              
    tcph->th_dport = cap_tcph.th_dport;

    tcph->th_seq = cap_tcph.th_seq;
    tcph->th_ack = 0;
    tcph->th_flags = TH_RST;
    tcph->th_win = cap_tcph.th_win;

    break;
  }


  tcph->th_off = sizeof(struct tcphdr)/4;

  tcph->th_sum = 0;
  tcph->th_urp = 0;

  /* generate tcp checksum */

  qh = (struct quasi_header *)checksum_data;
  tcp_ck = (struct tcphdr *)(checksum_data + sizeof(struct quasi_header));
  memset((void *)checksum_data, 0, ETHER_MAX_LEN);

  *tcp_ck = *tcph; 

  qh->ip_src = iph->ip_src;
  qh->ip_dst = iph->ip_dst;
  qh->ip_p = iph->ip_p;
  qh->th_off = htons( (u_short) sizeof(struct tcphdr) );

  tcph->th_sum = header_chksum((u_short *)checksum_data,
			   sizeof(struct quasi_header)+sizeof(struct tcphdr));


  len = sendto(sockfd, (void*)packet, len, 0,
	       (struct sockaddr *)&sa, sizeof(sa));

}


void discriminate_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  struct ether_header *eth;
  struct ip *iph;
  struct tcphdr *tcph;
  unsigned short len;
  char ip_src[16];
  char ip_dst[16];

  u_char *data;
  int tmp;

  eth = (struct ether_header*)p;

  sum_packet++;
    
  printf("\rCaptrue Packet:%7d  Capture ACK FLG:%4d  SYN FLG:%4d ",sum_packet,sum_ack,sum_syn);  
  fflush(stdout);

  if(ntohs(((struct ether_header *)p)->ether_type) != ETHERTYPE_IP) return;
  
  iph = (struct ip *)(p + sizeof(struct ether_header));

  if(iph->ip_p == IPPROTO_TCP){
    tcph = (struct tcphdr *)(p + sizeof(struct ether_header) + 4*iph->ip_hl);
    if(tcph->th_flags == TH_ACK || tcph->th_flags == TH_SYN)
      send_packet(*iph, *tcph);     
  }
}


void capture_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  struct ether_header *eth;
  struct ip *iph;
  struct tcphdr *tcph;
  unsigned short len;
  char ip_src[16];
  char ip_dst[16];

  u_char *data;
  int tmp;

  eth = (struct ether_header*)p;


  if(ntohs(((struct ether_header *)p)->ether_type) != ETHERTYPE_IP) return;
  
  iph = (struct ip *)(p + sizeof(struct ether_header));

  if(iph->ip_p == IPPROTO_TCP){
    tcph = (struct tcphdr *)
      (p + sizeof(struct ether_header) + 4 * iph->ip_hl);
    len = sizeof(struct ether_header) + (4 * iph->ip_hl) + (4 * tcph->th_off);
    data = (void *)(p + len);
    
    if(ntohs(iph->ip_len) < len) return;
    len = ntohs(iph->ip_len) - len + sizeof(struct ether_header);
    print_ipaddr(&iph->ip_src, ip_src);
    print_ipaddr(&iph->ip_dst, ip_dst);

    printf("\n========================================\n");
    printf("  %s:%d => %s:%d\n",ip_src,ntohs(tcph->th_sport),ip_dst,ntohs(tcph->th_dport));
    printf("=========================================\n");
    write(1,data,len);
    write(1,"\n\n",2);

    
  }
}
