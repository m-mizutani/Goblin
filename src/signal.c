#include "goblin.h"

void signal_handler(int sig)
{
  printf("\n\nexit normaly\n");
  pcap_close(pd);
  exit(0);
}

int set_sighdl(){
  /* signal handler set */

  struct sigaction act;

  act.sa_handler = signal_handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = NULL;

  return sigaction(SIGINT,&act,NULL);
}

