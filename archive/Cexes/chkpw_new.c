/*
 * This is a experimental software for creating adaptive typo tolerant password checking system.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

char *script_location = "./adaptive_typocheck.py";
int main(int argc, char *argv[])
{
    setuid( 0 );
    if (argc!=3) {
        printf("I need 3 arguments. You gave me %d!\n", argc);
        exit(1);
    }
    //          pythons script     +   username      +  password
    int t= strlen(script_location) + strlen(argv[1]) + strlen(argv[2]);
    char *script_arg = malloc(sizeof(char)*t);
    strcpy(script_arg, script_location);
    strcat(script_arg, " ");
    strcat(script_arg, argv[1]);
    strcat(script_arg, " ");
    strcat(script_arg, argv[2]);
    printf("%s\n", script_arg);
    system( script_arg );
    return 0;
}
