#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>



int main(int argc, char* argv[]) {
  // printf("Real uid: %d, effective uid: %d\n", getuid(), geteuid());
  seteuid(0); setuid(0);
  /* printf("Real uid: %d, effective uid: %d\n", getuid(), geteuid()); */
  /* printf("My process ID : %d\n", getpid()); */
  /* printf("My parent's ID: %d\n", getppid()); */
  char cmd[1000] = "/usr/local/bin/typtops.py";
  int i;
  int lim = strlen(cmd);
  /* if(argc<=2 || strcmp(argv[1], "--check")) */
  /*   return -1; */
  for(i=1; i<argc; i++) {
    if((lim+strlen(argv[i])) > 1000) break;
    sprintf(cmd, "%s %s", cmd, argv[i]);
  }
  system(cmd);
  return 0;
}
