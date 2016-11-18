/*-
 * Copyright (c) 2002-2003 Networks Associates Technology, Inc.
 * Copyright (c) 2004-2015 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

#ifndef OPENPAM
static char password_prompt[] = "Password:";
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

// #include "fix_pw.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <syslog.h>
#include <pwd.h>
#include <shadow.h>
#include <time.h>       /* for time() */
#include <errno.h>
#include <sys/wait.h>

#include <security/_pam_macros.h>

/* indicate that the following groups are defined */

#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

// #include "support.h"
// #include "passverify.h"

int _unix_run_verify_binary(pam_handle_t *pamh, unsigned int ctrl,
                            const char *user, int *daysleft)
{
    int retval=0, child, fds[2];
    struct sigaction newsa, oldsa;
    // D(("running verify_binary"));
    
    /* create a pipe for the messages */
    if (pipe(fds) != 0) {
        // D(("could not make pipe"));
        pam_syslog(pamh, LOG_ERR, "Could not make pipe: %m");
        return PAM_AUTH_ERR;
    }
    // D(("called."));
    
    if (off(UNIX_NOREAP, ctrl)) {
        /*
         * This code arranges that the demise of the child does not cause
         * the application to receive a signal it is not expecting - which
         * may kill the application or worse.
         *
         * The "noreap" module argument is provided so that the admin can
         * override this behavior.
         */
        memset(&newsa, '\0', sizeof(newsa));
        newsa.sa_handler = SIG_DFL;
        sigaction(SIGCHLD, &newsa, &oldsa);
    }
    
    /* fork */
    child = fork();
    if (child == 0) {
        static char *envp[] = { NULL };
        const char *args[] = { NULL, NULL, NULL, NULL };
        
        /* XXX - should really tidy up PAM here too */
        
        /* reopen stdout as pipe */
        if (dup2(fds[1], STDOUT_FILENO) != STDOUT_FILENO) {
            pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", "stdout");
            _exit(PAM_AUTHINFO_UNAVAIL);
        }
        
        if (pam_modutil_sanitize_helper_fds(pamh, PAM_MODUTIL_PIPE_FD,
                                            PAM_MODUTIL_IGNORE_FD,
                                            PAM_MODUTIL_PIPE_FD) < 0) {
            _exit(PAM_AUTHINFO_UNAVAIL);
        }
        
        if (geteuid() == 0) {
            /* must set the real uid to 0 so the helper will not error
               out if pam is called from setuid binary (su, sudo...) */
            if (setuid(0) == -1) {
                pam_syslog(pamh, LOG_ERR, "setuid failed: %m");
                printf("-1\n");
                fflush(stdout);
                _exit(PAM_AUTHINFO_UNAVAIL);
            }
        }
        
        /* exec binary helper */
        args[0] = CHKPWD_HELPER;
        args[1] = user;
        args[2] = "chkexpiry";
        
        execve(CHKPWD_HELPER, (char *const *) args, envp);
        
        pam_syslog(pamh, LOG_ERR, "helper binary execve failed: %m");
        /* should not get here: exit with error */
        // D(("helper binary is not available"));
        printf("-1\n");
        fflush(stdout);
        _exit(PAM_AUTHINFO_UNAVAIL);
    } else {
        close(fds[1]);
        if (child > 0) {
            char buf[32];
            int rc=0;
            /* wait for helper to complete: */
            while ((rc=waitpid(child, &retval, 0)) < 0 && errno == EINTR);
            if (rc<0) {
                pam_syslog(pamh, LOG_ERR, "unix_chkpwd waitpid returned %d: %m", rc)     retval = PAM_AUTH_ERR;
            } else if (!WIFEXITED(retval)) {
                pam_syslog(pamh, LOG_ERR, "unix_chkpwd abnormal exit: %d", retval);
                retval = PAM_AUTH_ERR;
            } else {
                retval = WEXITSTATUS(retval);
                rc = pam_modutil_read(fds[0], buf, sizeof(buf) - 1);
                if(rc > 0) {
                    buf[rc] = '\0';
                    if (sscanf(buf,"%d", daysleft) != 1 )
                        retval = PAM_AUTH_ERR;
                }
                else {
                    pam_syslog(pamh, LOG_ERR, "read unix_chkpwd output error %d: %m");
                    retval = PAM_AUTH_ERR;
                }
            }
        } else {
            pam_syslog(pamh, LOG_ERR, "Fork failed: %m");
            // D(("fork failed"));
            retval = PAM_AUTH_ERR;
        }
        close(fds[0]);
    }
    
    if (off(UNIX_NOREAP, ctrl)) {
        sigaction(SIGCHLD, &oldsa, NULL);   /* restore old signal handler */
    }
    
    // D(("Returning %d",retval));
    return retval;
}

/*
 * PAM framework looks for this entry-point to pass control to the
 * account management module.
 */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    unsigned int ctrl;
    const void *void_uname;
    const char *uname;
    int retval, daysleft;
    struct spwd *spent;
    struct passwd *pwent;
    char buf[256];
    
    // D(("called."));
    
    ctrl = _set_ctrl(pamh, flags, NULL, NULL, NULL, argc, argv);
    
    retval = pam_get_item(pamh, PAM_USER, &void_uname);
    uname = void_uname;
    // D(("user = `%s'", uname));
    if (retval != PAM_SUCCESS || uname == NULL) {
        pam_syslog(pamh, LOG_ALERT,
                   "could not identify user (from uid=%lu)",
                   (unsigned long int)getuid());
        return PAM_USER_UNKNOWN;
    }
    
    retval = get_account_info(pamh, uname, &pwent, &spent);
    if (retval == PAM_USER_UNKNOWN) {
        pam_syslog(pamh, LOG_ALERT,
                   "could not identify user (from getpwnam(%s))",
                   uname);
        return retval;
    }
    
    if (retval == PAM_SUCCESS && spent == NULL)
        return PAM_SUCCESS;
    
    if (retval == PAM_UNIX_RUN_HELPER) {
        retval = _unix_run_verify_binary(pamh, ctrl, uname, &daysleft);
        if (retval == PAM_AUTHINFO_UNAVAIL &&
            on(UNIX_BROKEN_SHADOW, ctrl))
            return PAM_SUCCESS;
    } else if (retval != PAM_SUCCESS) {
        if (on(UNIX_BROKEN_SHADOW,ctrl))
            return PAM_SUCCESS;
        else
            return retval;
    } else
        retval = check_shadow_expiry(pamh, spent, &daysleft);
    
    if (on(UNIX_NO_PASS_EXPIRY, ctrl)) {
        const void *pretval = NULL;
        int authrv = PAM_AUTHINFO_UNAVAIL; /* authentication not called */
        
        if (pam_get_data(pamh, "unix_setcred_return", &pretval) == PAM_SUCCESS
            && pretval)
            authrv = *(const int *)pretval;
        
        if (authrv != PAM_SUCCESS
            && (retval == PAM_NEW_AUTHTOK_REQD || retval == PAM_AUTHTOK_EXPIRED))
            retval = PAM_SUCCESS;
    }
    
    switch (retval) {
    case PAM_ACCT_EXPIRED:
        pam_syslog(pamh, LOG_NOTICE,
                   "account %s has expired (account expired)",
                   uname);
        _make_remark(pamh, ctrl, PAM_ERROR_MSG,
                     _("Your account has expired; please contact your system adminis"));
        break;
    case PAM_NEW_AUTHTOK_REQD:
        if (daysleft == 0) {
            pam_syslog(pamh, LOG_NOTICE,
                       "expired password for user %s (root enforced)",
                       uname);
            _make_remark(pamh, ctrl, PAM_ERROR_MSG,
                         _("You are required to change your password immediately (ad enforced)"));
        } else {
            pam_syslog(pamh, LOG_DEBUG,
                       "expired password for user %s (password aged)",
                       uname);
            _make_remark(pamh, ctrl, PAM_ERROR_MSG,
                         _("You are required to change your password immediately (pa expired)"));
        }
        break;
    case PAM_AUTHTOK_EXPIRED:
        pam_syslog(pamh, LOG_NOTICE,
                   "account %s has expired (failed to change password)",
                   uname);
        _make_remark(pamh, ctrl, PAM_ERROR_MSG,
                     _("Your account has expired; please contact your system adminis"));
        break;
    case PAM_AUTHTOK_ERR:
        retval = PAM_SUCCESS;
        /* fallthrough */
    case PAM_SUCCESS:
        if (daysleft >= 0) {
            pam_syslog(pamh, LOG_DEBUG,
                       "password for user %s will expire in %d days",
                       uname, daysleft);
#if defined HAVE_DNGETTEXT && defined ENABLE_NLS
            snprintf (buf, sizeof (buf),
                      dngettext(PACKAGE,
                                "Warning: your password will expire in %d day",
                                "Warning: your password will expire in %d days",
                                daysleft),
                      daysleft);
#else
            if (daysleft == 1)
                snprintf(buf, sizeof (buf),
                         _("Warning: your password will expire in %d day"),
                         daysleft);
            else
                snprintf(buf, sizeof (buf),
                         /* TRANSLATORS: only used if dngettext is not supported */
                         _("Warning: your password will expire in %d days"),
                         daysleft);
#endif
            _make_remark(pamh, ctrl, PAM_TEXT_INFO, buf);
        }
    }
    
    // D(("all done"));
    
    return retval;
}


PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char *argv[])
{
#ifndef OPENPAM
	struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
#endif
	struct passwd *pwd;
	const char *user;
	const char *crypt_password, *password;
	int pam_err, retry;

	(void)argc;
	(void)argv;
    printf("Using new (typotplerant) pam module! (openpam)\n");
	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if ((pwd = getpwnam(user)) == NULL)
		return (PAM_USER_UNKNOWN);

	/* get password */
#ifndef OPENPAM
	pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (pam_err != PAM_SUCCESS)
		return (PAM_SYSTEM_ERR);
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = password_prompt;
	msgp = &msg;
#endif
	for (retry = 0; retry < 3; ++retry) {
#ifdef OPENPAM
		pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
                                  &password, NULL);
#else
		resp = NULL;
		pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
		if (resp != NULL) {
			if (pam_err == PAM_SUCCESS)
				password = resp->resp;
			else
				free(resp->resp);
			free(resp);
		}
#endif
		if (pam_err == PAM_SUCCESS)
			break;
	}
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);
	/* compare passwords */
    /* If the entered password is null, fail immediately */
    int success = 0;
	if (!pwd->pw_passwd[0] && (flags & PAM_DISALLOW_NULL_AUTHTOK))
        success = 0;
    else {
        /* Check the original first */
        printf("pwd->pw_passwd: %s\n", pwd->pw_passwd);
        if (((crypt_password = crypt(password, pwd->pw_passwd)) != NULL) &&
            strcmp(crypt_password, pwd->pw_passwd) == 0) {
            success = 1;  // If it succeeds, then set pam_success and don't do anything
            printf("Failed: %s\t\t<%s>\t\t%s\n", password, pwd->pw_passwd,crypt_password);
        } else { // if the comparison with entered password fails, try possible fixes
            printf("Trying possible typo fixes!!\n Total %d combinations.\n", NFIXES);
            int i = 0;
            char **fixed = fix_passwords(password); // obtain possible fixes
            for(i = 0; i<NFIXES; i++) {
                printf("trying corrected pw: <%s>\t\t<%s>\n", fixed[i], pwd->pw_passwd);
                if(!fixed[i] || fixed[i][0] == '\0') // probably malformed fix
                    continue;
                crypt_password = crypt(fixed[i], pwd->pw_passwd);
                if ((crypt_password != NULL) && (strcmp(crypt_password, pwd->pw_passwd) == 0)) {
                    success = 1;
                    break;
                }
                printf("Failed: %s\t\t%s\t\t%s\n", password, pwd->pw_passwd,crypt_password);
            }
        }
    }
    printf("Success: %d\n", success);
    if (success == 1)
        pam_err = PAM_SUCCESS;
    else
        pam_err = PAM_AUTH_ERR;
#ifndef OPENPAM
	free(password);
#endif
	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
               int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                 int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_typopw");
#endif
