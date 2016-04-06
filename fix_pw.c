#include "fix_pw.h"


const char *shiftmap[2] = {"`1234567890-=[]\\;',./", "~!@#$%^&*()_+{}|:\"<>?"};

char swapcase(char c) {
  if (isupper(c))
    return tolower(c);
  if (islower(c))
    return toupper(c);
  return c;
}

char swapshift(char c) {
  int i=0;
  for(i=0; i<strlen(shiftmap[0]); i++) {
      if (shiftmap[0][i] == c)
        return shiftmap[1][i];
      else if (shiftmap[1][i] == c)
        return shiftmap[0][i];
  }
  return c;
}

void swcaseall(const char *pw, char *ret){
  while(*pw){
    printf(">>> %s <-> %s\n", pw, ret);
    *ret++ = swapcase(*pw++);
  }
}

void swcasefirst(const char *pw, char *ret){
  strcpy(ret, pw);
  ret[0] = swapcase(ret[0]);
}

void swcasefirstl(const char *pw, char *ret){
  // Switch the case of first *letter*
  strcpy(ret, pw);
  while(!isalpha(*ret)) ret++;
  ret[0] = swapcase(ret[0]);
}

void rmlastch(const char *pw, char *ret) {
  strcpy(ret, pw);
  int n = strlen(pw);
  ret[n-1] = '\0';
}

void rmfirstch(const char *pw, char *ret) {
  strcpy(ret, pw+1);
}

void swslastone(const char *pw, char *ret) {
  strcpy(ret, pw);
  int n = strlen(ret);
  ret[n-1] = swapshift(ret[n-1]);
}


char** fix_passwords(const char* pw) {
  char **fixes = (char **) malloc(sizeof(char*) * NFIXES);
  bzero((void*)fixes, NFIXES);
  int n = strlen(pw)+1, i=0;
  char *tmp =  (char*) malloc(sizeof(char) * n);
  int fcnt = 0;
  for(i=0; i<NFIXES; i++) {
    printf("pw = %s\n", pw);
    printf("tmp = %x<->%x\n", tmp, tmp+n);
    switch(i) {
    case swcall:
      swcaseall(pw, tmp);
      break;
    case swcfirst:
      swcasefirst(pw, tmp);
      break;
    case rmlast:
      rmlastch(pw, tmp);
      break;
    case rmfirst:
      rmfirstch(pw, tmp);
      break;
    case swcfirstl:
      swcasefirstl(pw, tmp);
      break;
    case swslast:
      swslastone(pw, tmp);
      break;
    default:
      break;
    }
    if (strcmp(tmp, pw) != 0) {  // if the value of 'fix' is not the same as the input    
      int j=0;
      // And it is not already in the fixes list
      for(; j<fcnt; j++) { 
        if (strcmp(fixes[j], tmp)==0) 
          break;
      }
      if (j>=fcnt) {
        fixes[i] = (char*) malloc(sizeof(char) * n);
        strcpy(fixes[i], tmp);
        fcnt++;
      }
    }
  }
  return fixes;
}
  
