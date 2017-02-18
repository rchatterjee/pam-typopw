#define _XOPEN_SOURCE 700

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>

const int TYPTOP_COLLECT = 1;
const int TYPTOP_FIN = 2;

static int
call_typtop(pam_handle_t *pamh, const char* user, const char* passwd, int chkwd_ret) {
    char cmd[1000];
    sprintf(cmd, "/usr/local/bin/typtop --check %s %s %d", 
            user, passwd, chkwd_ret==0?0:1);
    int retval = PAM_AUTH_ERR;
    if ((strlen(user) + strlen(passwd))>150)
        retval = PAM_AUTH_ERR;
    // printf("cmd=%s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL || fscanf(fp, "%d", &retval)<=0) {
        printf("Typtop could not be opened. Sorry! retval=%d\n", retval);
    } 
    return retval;
}

/*  Runs TypToP, fetching the entered password using `pam_get_authtok`
    If 
*/
__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret_pam_unix = PAM_SUCCESS;  // default ret_pam_unix is pam_failure
    int retval;
    const char *name;
    const char *passwd;
    int i;
    for(i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "incorrect_pass")) {
            ret_pam_unix = PAM_AUTH_ERR;
        }
    }

    if (ret_pam_unix == PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "user entered the correct pw!");
    } else {
        pam_syslog(pamh, LOG_NOTICE, "incorrect password entered");
    }

    if (pam_get_user(pamh, &name, NULL) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "couldn't get username from PAM stack");
        return PAM_USER_UNKNOWN;
    }

    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &passwd, "this shouldn't be displayed... try entering a password");
    if (retval != PAM_SUCCESS || passwd == NULL) {
        pam_syslog(pamh, LOG_WARNING, "couldn't find cached password or password is blank");
        return PAM_IGNORE;
    } else {
        retval = call_typtop(pamh, name, passwd, ret_pam_unix);
        if (retval == 0){
            if (ret_pam_unix == 0) {
                pam_syslog(pamh, LOG_NOTICE, "called typtop with correct pw");
            } else {
                pam_syslog(pamh, LOG_NOTICE, "typtop allowed typo-ed password");
            }
            return PAM_SUCCESS;
        } else {
            pam_syslog(pamh, LOG_NOTICE, "typtop either failed or check did not pass. retval=%d", retval);
            return ret_pam_unix;
        }
    }
    return ret_pam_unix; // Should never reach here.
}


__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags,
        int argc, const char **argv)
{
    return PAM_SUCCESS;
}
