#ifndef _RUN_PROC_H
#define _RUN_PROC_H

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#ifndef __APPLE__
#  include <security/_pam_macros.h>
#  include <security/pam_ext.h>
#  include <security/pam_modutil.h>
#else
#  include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

// # include <syslog.h>

static int
check_with_typtop(const char *user, const char *passwd, int old_pam_retval) {
    pid_t pid = 0;
    int pipefd_read[2], pipefd_write[2];
    char buf[256];
    int typtop_retval = old_pam_retval;
    if (pipe(pipefd_read)<0 || pipe(pipefd_write)<0) {
        //syslog(LOG_CRIT, "Pipe failed. Returning what original pam returned.");
        return old_pam_retval;
    }
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
        close(pipefd_write[1]); close(pipefd_read[0]);
        sprintf(buf, "%d", old_pam_retval);
        char *typtopexe = "/usr/local/bin/typtop";
        execl(typtopexe, typtopexe, "--check", buf, user, (char*) NULL);
        // execl("./run_as_root", "./run_as_root", "--check", buf, user, (char*) NULL);
        exit(1);
    }
    else {
        int status;
        if(waitpid(pid, &status, WNOHANG) != 0) {
            //syslog(LOG_NOTICE, "WTF! Whty the child is dead!\n");
            perror("WTF! Whty the child is dead!\n");
        }
        close(pipefd_read[0]); 
        close(pipefd_write[1]);
        if(write(pipefd_read[1], passwd, strlen(passwd))<0) {
            //syslog(LOG_CRIT, "Sorry write to the child typtop process failed.");
            perror("Sorry write to the child typtop process failed.");
        }
        close(pipefd_read[1]);
        if (read(pipefd_write[0], buf, 256)>0) {
            sscanf(buf, "%d", &typtop_retval);
        }
        else {
            perror("Could not read from typtop. Sorry\n");
            //syslog(LOG_CRIT, "Could not read from typtop. Sorry\n");
        }
        close(pipefd_write[0]);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        //syslog(LOG_CRIT, "Returning from run_proc: typtop_retval=%d", typtop_retval);
        return typtop_retval;
    }
}

#endif
