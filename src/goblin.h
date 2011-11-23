#ifndef GOBLIN_H
#define GOBLIN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <pcap.h>

#define DEFAULT_LEN 1500

#define VERSION "0.2.0"

struct quasi_header{ 
  struct in_addr ip_src;
  struct in_addr ip_dst;
  u_char x0;
  u_char ip_p;
  u_short th_off;
};

struct option{
  int i; /* device name specifed     [arg(str)/false] */
  int c; /* condition specifed       [arg(str)/false] */
  int m; /* mode option              [arg(str)/false] */
  int t; /* timeout N msec           [arg(N)/false]   */
  int v; /* show version (only this) [true/false]     */ 
} option;

pcap_t *pd;       /* pcap discripter for pacet capturing */
int sockfd, on;   /* socket discripter for packet send */
char mode;

/* t:tail mode
 * r:RST daemon mode
 */

int sum_packet;
int sum_ack;
int sum_syn;


/* packet.c */
u_short header_chksum(u_short *ptr, int nbytes);
void print_ipaddr(struct in_addr *ip_addr, char *ip_buf);
void send_packet(struct ip cap_iph, struct tcphdr cap_tcph);

void discriminate_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void capture_packet     (u_char *user, const struct pcap_pkthdr *h, const u_char *p);

/* option.c */
int get_option(int argc, char **argv);
char set_mode(char **argv);
int set_timeout(char mode, char **argv);

/* signal.c */
int set_sighdl();

#endif /* GOBLIN_H */
