#include "fix_pw.h"
#include <time.h>

int test1() {
  const char* s = "Rahul12!";
  int i = 0;
  char **fixes = fix_passwords(s);
  if (strcmp(fixes[0], "Rahul12!") != 0)
    printf("ERROR (swcall): Got: %s\n", fixes[0]);
  if (strcmp(fixes[1], "rAHUL12!") != 0)
    printf("ERROR (swcall): Got: %s\n", fixes[0]);
  if (strcmp(fixes[2], "rahul12!") != 0)
    printf("ERROR (swcfirst): Got: %s\n", fixes[1]);
  if (strcmp(fixes[3], "Rahul12") != 0)
    printf("ERROR (rmlast): Got: %s\n", fixes[2]);
  if (strcmp(fixes[4], "Rahul121") != 0)
    printf("ERROR (swslast): Got: %s\n", fixes[3]);
  if (strcmp(fixes[5], "ahul12!") != 0)
    printf("ERROR (rmfirst): Got: %s\n", fixes[4]);
  if (fixes[6] != 0)
    printf("ERROR (swcfirstl): Got: %x\n", fixes[5]);
  return 0;
}


int main(int argc, char** argv) {
  if (argc<2) {
    printf("USAGE: \n$ %s <password>\n", argv[0]);
    return 0;
  }

  FILE* fp = fopen("tmp.bin", "r");
  if (!fp)
    printf("FIle could not be opened!\n");
  int attempt=0;
  unsigned timestamp_now = time(NULL);
  unsigned timestamp_old = 0;
  fscanf(fp, "%d,%d", &attempt, &timestamp_old);
  printf("timestamp=%u, attempt=%d\n", timestamp_old, attempt);

  /* test1(); */
  /* int i=0; */
  /* char **fixes = fix_passwords(argv[1]); */
  /* for(i=0; i<NFIXES; i++) { */
  /*   printf("%x\t\t", fixes[i]); */
  /*   if (fixes[i]) */
  /*     printf("%s\n", fixes[i]); */
  /* } */
  /* return 0; */
}


