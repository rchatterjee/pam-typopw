#define _XOPEN_SOURCE 700


#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>

#ifndef __APPLE__
#  include <security/_pam_macros.h>
#  include <security/pam_ext.h>
#  include <security/pam_modutil.h>
#else
#  include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

const int TYPTOP_COLLECT = 1;
const int TYPTOP_FIN = 2;

#ifdef __APPLE__
/* pam_syslog is missing in apple, this is a function taken from
   https://git.reviewboard.kde.org/r/125056/diff/3#4
*/
void pam_vsyslog(const pam_handle_t *ph, int priority, const char *fmt, va_list args)
{
  char *msg = NULL;
  const char *service = NULL;
  int retval;
  retval = pam_get_item(ph, PAM_SERVICE, (const void **) &service);
  if (retval != PAM_SUCCESS)
    service = NULL;

  if (vasprintf(&msg, fmt, args) < 0) {
    syslog(LOG_CRIT | LOG_AUTHPRIV, "cannot allocate memory in vasprintf: %m");
    return;
  }
  syslog(priority | LOG_AUTHPRIV, "%s%s%s: %s",
         (service == NULL) ? "" : "(",
         (service == NULL) ? "" : service,
         (service == NULL) ? "" : ")", msg);
  free(msg);
}

void pam_syslog(const pam_handle_t *ph, int priority, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  pam_vsyslog(ph, priority, fmt, args);
  va_end(args);
}
#endif

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
    fclose(fp);
    return retval;
}

/*  Runs TypToP, fetching the entered password using `pam_get_authtok`
    If
*/
__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret_pam_unix = PAM_SUCCESS;  // default ret_pam_unix is pam_failure
    int retval = PAM_AUTH_ERR;
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
            if (ret_pam_unix == PAM_SUCCESS) {
                pam_syslog(pamh, LOG_NOTICE, "called typtop with correct pw");
            } else {
                pam_syslog(pamh, LOG_NOTICE, "typtop allowed typo-ed password");
            }
            pam_syslog(pamh, LOG_NOTICE, "returning PAM_SUCCESS.");
            retval = PAM_SUCCESS;
            return retval;
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
    int retval = PAM_SUCCESS;
    pam_syslog(pamh, LOG_NOTICE, "called pam_sm_setcred. flag=%d", flags);
    return retval;
}

/* For debugging */
__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, const char *argv[])
{
    pam_syslog(pamh, LOG_NOTICE, "called pam_sm_open_session. Return ignore.");
    return (PAM_IGNORE);
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
                     int argc, const char *argv[])
{
    pam_syslog(pamh, LOG_NOTICE, "called pam_sm_close_session. Return ignore.");
    return (PAM_IGNORE);
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                 int argc, const char *argv[])
{
    pam_syslog(pamh, LOG_NOTICE, "called pam_sm_chauthtok. Return service error.");
    return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_typtop");
#endif
