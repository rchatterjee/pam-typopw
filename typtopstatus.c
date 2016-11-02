#include<stdio.h>
#include<string.h>
int main(int argc, char* argv[]) {
    if (argc<2) {
        printf("Usfage: %s <username>\n", argv[0]);
        return 1;
    }
    if (strlen(argv[1])>900) {
        printf("Username too long. Not allowed\n");
        return 1;
    }
    char cmd[1000];
    sprintf(cmd, "/usr/local/bin/typtop --status %s", argv[1]);
    return system(cmd);
}
