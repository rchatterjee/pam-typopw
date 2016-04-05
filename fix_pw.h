#ifndef __FIX_PW__
#define __FIX_PW__
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>

enum FIX_TYPE {swcall=0, swcfirst, rmlast, swslast, rmfirst, swcfirstl};

#define NFIXES 6

char **fix_passwords(const char*pw);

#endif
