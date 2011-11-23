#include "goblin.h"


int init_socks(){
  pd = NULL;
  on = 1;

  if(( sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
    perror("socket");
    exit(1);
  }

  if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
    perror("setsockopt");
    exit(1);
  }

}

int main(int argc, char **argv){
  /* using device name */
  char *device_name;

  /* pcap error message buffer */
  char ebuf[PCAP_ERRBUF_SIZE];

  /* pcap_compile */
  char *cmdbuf;
  int Oflag = 1;
  struct bpf_program fcode;
  bpf_u_int32 localnet, netmask; 

  int timeout = 1000;


  if(set_sighdl() < 0){
    perror("set signal handler(SIGINT):");
    exit(1);
  }

  if(!get_option(argc, argv)){
    printf("Syntax Error...\n");
    printf("Usage:goblin [-i interface] [-c \"condition\"] [-m rst/tail] [-t n(msec)]\n");
    exit(1);
  }

  sum_packet = 0;
  sum_ack = 0;
  sum_syn = 0;


  if((mode = set_mode(argv)) == 0){
    printf("Undefined Mode (\"rst\" or \"tail\")\n");
    exit(1);
  }

  if((timeout = set_timeout(mode,argv)) == 0){
    printf("Illigal Time  < 0\n");
    exit(1);
  }
	   
  init_socks();
  
  if(option.i != 0){
    device_name = (char*)malloc( (strlen(argv[option.i]) + 1) * sizeof(char) );
    strcpy(device_name,argv[option.i]);
  }
  else{
    if((device_name = pcap_lookupdev(ebuf)) == NULL){
      fprintf(stderr,"%s\n",ebuf);
      exit(1);
    }
  }

  printf("PROMISC DEV: %s\n",device_name);
  //  pd = pcap_open_live(device_name, DEFAULT_LEN, 1, 1000, ebuf);
  pd = pcap_open_live(device_name, ETHER_MAX_LEN, 1, timeout, ebuf);
  if(option.i != 0) free(device_name);

  if(pd == NULL){
    fprintf(stderr,"%s\n",ebuf);
    exit(1);
  }

  if (pcap_lookupnet(device_name, &localnet, &netmask, ebuf) < 0) {
    localnet = 0;
    netmask = 0;
    fprintf(stderr,"%s", ebuf);
    exit(1);
  }

  if(option.c != 0){
    cmdbuf = argv[option.c];
    if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0){
      fprintf(stderr,"%s", pcap_geterr(pd));
      exit(1);
    }
    if (pcap_setfilter(pd, &fcode) < 0){
      fprintf(stderr,"%s", pcap_geterr(pd));
      exit(1);
    }
  }


  switch(mode){
  case 't':
    if( pcap_loop(pd, -1, capture_packet, NULL) < 0 ){
      fprintf(stdout,"pcap_loop:%s\n",pcap_geterr(pd));
      exit(1);
    }
    break;

  case 'r':
    if( pcap_loop(pd, -1, discriminate_packet, NULL) < 0 ){
      fprintf(stdout,"pcap_loop:%s\n",pcap_geterr(pd));
      exit(1);
    }
    break;
  }

  return 0;
}
