#ifndef _RUN_PROC_H
#define _RUN_PROC_H

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>

static int
check_with_typtop(const char *user, const char *passwd, int old_pam_retval) {
    pid_t pid = 0;
    int pipefd_read[2], pipefd_write[2];
    char buf[256];
    int typtop_retval = old_pam_retval;
    pipe(pipefd_read); pipe(pipefd_write);
    pid = fork();
    if (pid == 0) {      // Child
      close(pipefd_read[1]);
      close(pipefd_write[0]);

      if (dup2(pipefd_read[0], STDIN_FILENO) < 0 ||
          dup2(pipefd_write[1], STDOUT_FILENO) < 0 ||
          dup2(pipefd_write[1], STDERR_FILENO) < 0
          ) {
        printf("%d", 1);
        exit(1);
      }
      sprintf(buf, "%d", old_pam_retval);
      // execle("/usr/local/bin/typtop", "--check", buf, user, (char*) NULL);
      execl("./run_as_root", "./run_as_root", "--check", buf, user, (char*) NULL);

      exit(1);
    }
    int status;
    if(waitpid(pid, &status, WNOHANG) != 0) {
      printf("WTF! Whty the child is dead!\n");
    }

    close(pipefd_read[0]); close(pipefd_write[1]);
    write(pipefd_read[1], passwd, strlen(passwd)); // write message to the process
    close(pipefd_read[1]);
    if (read(pipefd_write[0], buf, 256)>0) {
      sscanf(buf, "%d", &typtop_retval);
    }
    else
        printf("Could not read from typtop. Sorry\n");
    close(pipefd_write[0]);
    return typtop_retval;
}

#endif
