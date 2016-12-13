#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define PAM_SUCCESS 0
#define PAM_AUTH_ERR 1
int main(int argc, char *argv[]) {
  int retval = PAM_AUTH_ERR;
  char * user = "rahul";
  char *password = argv[1];
  /* Check the typo tolerance here. */
  char *_cmd = (char *)malloc(sizeof(char) * (30 + strlen(user) + strlen(password)));
  sprintf(_cmd, "python typtop --check 1 %s %s", user, password);
  FILE *fp = popen(_cmd, "r");
  if (fp == NULL) {
    printf("Typtop could not be opened. Sorry!\n");
  } else {
    int ret = retval;
    fscanf(fp, "%d", &ret);
    if (ret == PAM_SUCCESS)
      retval = PAM_SUCCESS;
  }
  printf("retval=%d\n", retval);
  return retval;
}
