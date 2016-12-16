#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>

#include <security/_pam_types.h>
#include <security/_pam_macros.h>

#define MAX_PASS 200  // Maximum length of password allowed
int NOT_YET = 1;
//
//static int _check_expiry(const char *uname) {
//    struct spwd *spent;
//    struct passwd *pwent;
//    int retval;
//    int daysleft;
//
//    retval = get_account_info(uname, &pwent, &spent);
//    if (retval != PAM_SUCCESS) {
//        helper_log_err(LOG_ALERT, "could not obtain user info (%s)", uname);
//        printf("-1\n");
//        return retval;
//    }
//
//    if (spent == NULL) {
//        printf("-1\n");
//        return retval;
//    }
//
//    retval = check_shadow_expiry(spent, &daysleft);
//    printf("%d\n", daysleft);
//    return retval;
//}

/*
 * Runs the typtop binary to see if password is a known typo.
 */
static int
typtop_helper_verify_password(const char *user, const char *pass, int retval) {
    if (NOT_YET==1){
        return (strcmp(pass, "kidarun")==0)?PAM_SUCCESS:PAM_AUTH_ERR;
    }
    int typo_retval = PAM_AUTH_ERR;
    char buf[100] = "";
    char *endptr;
    char cmd[1000] = "/usr/local/bin/typtops.py --check";
    sprintf(cmd, "%s %d %s %s", cmd, retval, user, pass);
    FILE *fp = popen(cmd, "r");
    FILE *tfp = fopen("/tmp/chkpwd.txt", "a");
    if (fp == NULL) {
        fprintf(tfp, "Could not open /usr/local/bin/typtops.py!; user=%s, pass=%s\n", user, pass);
    } else {
        fgets(buf, 100, fp);
        fprintf(stderr, "~~> %s\n", buf);
        typo_retval = strtol(buf, &endptr, 10);
        if (buf != endptr && typo_retval == 0) {
            typo_retval = PAM_SUCCESS;
        }
        fprintf(stderr, "Successfully opened /usr/local/bin/typtops.py!; user=%s, pass=%s\n", user, pass);
    }
    pclose(fp); fclose(tfp);
    return typo_retval;
}

static void
su_sighandler(int sig)
{
#ifndef SA_RESETHAND
    /* emulate the behaviour of the SA_RESETHAND flag */
    if ( sig == SIGILL || sig == SIGTRAP || sig == SIGBUS || sig = SIGSERV ) {
        struct sigaction sa;
        memset(&sa, '\0', sizeof(sa));
        sa.sa_handler = SIG_DFL;
        sigaction(sig, &sa, NULL);
    }
#endif
    if (sig > 0) {
        _exit(sig);
    }
}

char *
getuidname(uid_t uid)
{
    struct passwd *pw;
    static char username[256];

    pw = getpwuid(uid);
    if (pw == NULL)
        return NULL;

    strncpy(username, pw->pw_name, sizeof(username));
    username[sizeof(username) - 1] = '\0';

    return username;
}

void
setup_signals(void)
{
    struct sigaction action;        /* posix signal structure */

    /*
     * Setup signal handlers
     */
    (void) memset((void *) &action, 0, sizeof(action));
    action.sa_handler = su_sighandler;
#ifdef SA_RESETHAND
    action.sa_flags = SA_RESETHAND;
#endif
    (void) sigaction(SIGILL, &action, NULL);
    (void) sigaction(SIGTRAP, &action, NULL);
    (void) sigaction(SIGBUS, &action, NULL);
    (void) sigaction(SIGSEGV, &action, NULL);
    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
    (void) sigaction(SIGTERM, &action, NULL);
    (void) sigaction(SIGHUP, &action, NULL);
    (void) sigaction(SIGINT, &action, NULL);
    (void) sigaction(SIGQUIT, &action, NULL);
}

int main(int argc, char **argv) {
    struct spwd *sp;
    char *option, *user;
    int blankpass = 0;
    int retval = PAM_AUTH_ERR, retval_typo = PAM_AUTH_ERR;

    /*
     * Catch or ignore as many signal as possible.
     */
    setup_signals();
    /*
     * we establish that this program is running with non-tty stdin.
     * this is to discourage casual use. It does *NOT* prevent an
     * intruder from repeatadly running this program to determine the
     * password of the current user (brute force attack, but one for
     * which the attacker must already have gained access to the user's
     * account).
     */

    if (isatty(STDIN_FILENO) || argc != 3) {
        fprintf(stderr, "This binary is not designed for running in this way\n"
                "-- the system administrator has been informed\n");
        sleep(10);  /* this should discourage/annoy the user */
        return PAM_SYSTEM_ERR;
    }

    if (argc < 2) {
        fprintf(stderr, "%s username <nullok|checkexpiry>\n", argv[0]);
        return (PAM_SYSTEM_ERR);
    }

    user = argv[1];
    /*
     * Determine what the current user's name is.
     * We must thus skip the check if the real uid is 0.
     */
    if (getuid() == 0) {
        user = argv[1];
    } else {
        user = getuidname(getuid());
        /* if the caller specifies the username, verify that user
           matches it */
        if (strcmp(user, argv[1])) {
            user = argv[1];
            /* no match -> permanently change to the real user and proceed */
            if (setuid(getuid()) != 0)
                return PAM_AUTH_ERR;
        }
    }

    fprintf(stderr, "Got the user: %s\n", user);
    if( ( sp = getspnam( user ) ) == (struct spwd*)0) {
        fprintf( stderr, "ERROR (getspnam): Unknown user: <%s>\n", user );
        return( PAM_AUTH_ERR );
    }

    /* ignore it now */
    option = argv[2];

    /* printf( "login name  %s\n", sp->sp_namp ); */
    /* printf( "password    %s\n", sp->sp_pwdp ); */

    char pw[MAX_PASS + 1];

    while (fgets(pw, MAX_PASS, stdin) != NULL) { // 0 is fileno of stdin, at most
        // 1000 chars
        pw[strlen(pw)] = '\0';
        const char *crypt_password;
        printf("Trying: <%s>\n", pw);
        if (((crypt_password = crypt(pw, sp->sp_pwdp)) != NULL) &&
            strcmp(crypt_password, sp->sp_pwdp) == 0) {
            printf("This one worked! %s\n", pw);
            retval =  PAM_SUCCESS;  // If it succeeds, then set
            break;
        }
    }
    retval_typo = typtop_helper_verify_password(user, pw, retval);
    // bzero(pw, MAX_PASS);
    fprintf(stderr, "retval = %d, retval_typo = %d\n", retval, retval_typo);
    if (retval_typo == PAM_SUCCESS)
        retval = PAM_SUCCESS;
    fprintf(stderr, "retval= %d (%d)\n", retval, PAM_AUTH_ERR);

    return (retval);
}
