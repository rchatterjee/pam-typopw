#include "fix_pw.h"
int main(int argc, char** argv) {
  if (argc<2) {
    printf("USAGE: \n$ %s <password>\n", argv[0]);
    return 0;
  }
  int i=0;
  char **fixes = fix_passwords(argv[1]);
  for(i=0; i<NFIXES; i++) {
    if (fixes[i])
      printf("%s\n", fixes[i]);
  }
  return 0;
}
