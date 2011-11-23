#include "goblin.h"

int get_option(int argc, char **argv)
{
  int argp;

  option.i = 0;
  option.c = 0;
  option.t = 0;
  option.m = 0;
  option.v = 0;

  for(argp = 1; argp < argc; argp++){
    if     ( strcmp(argv[argp],"-i") == 0) option.i = ++argp;
    else if( strcmp(argv[argp],"-c") == 0) option.c = ++argp;
    else if( strcmp(argv[argp],"-t") == 0) option.t = ++argp;
    else if( strcmp(argv[argp],"-m") == 0) option.m = ++argp;
    else if( strcmp(argv[argp],"-v") == 0) option.v = 1;
    else return 0;
  }

  if(option.v == 1){
    printf("goblin version ");
    printf(VERSION);
    printf("\npowered by Mizutani. Use to \"SING\" Tutorial Demonstration.\n\n");
    exit(0);
  }

  if(option.i == argc || 
     option.c == argc ||
     option.t == argc ||
     option.m == argc ) return 0;

  return 1;
}

char set_mode(char **argv)
{
  if(option.m != 0){
    if     (strcmp(argv[option.m],"rst")  == 0) return 'r';
    else if(strcmp(argv[option.m],"tail") == 0) return 't';
    else return 0;
  }
  else return 'r';
}

int set_timeout(char mode, char **argv)
{
  int timeout;

  if(mode == 'r') return 1;

  if(option.t != 0){
    timeout = atoi( argv[option.t] );
    if( timeout <= 0 )
      return 0;
    else
      return timeout;
  }

  return 1000;
}
