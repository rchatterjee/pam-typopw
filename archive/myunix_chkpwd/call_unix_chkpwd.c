#include <stdio.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <Python.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CHKPWD_HELPER "/sbin/unix_chkpwd"

int call_typtop(const char* user, const char* passwd, int chkwd_ret) {
    PyObject *pModule, *pName, *pFunc;
    PyObject *pArgs, *pValue;

    Py_Initialize();
    pName = PyString_FromString("typtop.dbaccess");
    
    /* Error checking of pName left out */
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, "call_check");
        /* pFunc is a new reference */

        if (pFunc && PyCallable_Check(pFunc)) {
            pArgs = PyTuple_New(3);
            /* Set the argumnet for the function*/
            PyTuple_SetItem(pArgs, 0, PyInt_FromLong(chkwd_ret));
            PyTuple_SetItem(pArgs, 1, PyString_FromString(user));
            PyTuple_SetItem(pArgs, 2, PyString_FromString(passwd));

            pValue = PyObject_CallObject(pFunc, pArgs);
            Py_DECREF(pArgs);
            if (pValue != NULL) {
                printf("Result of call: %ld\n", PyInt_AsLong(pValue));
                int ret = PyInt_AsLong(pValue);
                Py_DECREF(pValue);
                return ret;
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                fprintf(stderr,"Call failed\n");
                return 1;
            }
        }
        else {
            if (PyErr_Occurred())
                PyErr_Print();
            fprintf(stderr, "Cannot find function \"%s\"\n", "call_check");
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", "typtop.dbaccess");
        return 1;
    }
    Py_Finalize();
    return 1;
}


int 
_unix_run_helper_binary(const char *passwd,
                        unsigned int ctrl, const char *user)
{
    int retval, child, fds[2];
    // struct sigaction newsa, oldsa;

    // D(("called."));
    /* create a pipe for the password */
    if (pipe(fds) != 0) {
        // D(("could not make pipe"));
        return PAM_AUTH_ERR;
    }

    /* if (off(UNIX_NOREAP, ctrl)) { */
	/* /\* */
	/*  * This code arranges that the demise of the child does not cause */
	/*  * the application to receive a signal it is not expecting - which */
	/*  * may kill the application or worse. */
	/*  * */
	/*  * The "noreap" module argument is provided so that the admin can */
	/*  * override this behavior. */
	/*  *\/ */
    /*     memset(&newsa, '\0', sizeof(newsa)); */
	/* newsa.sa_handler = SIG_DFL; */
	/* sigaction(SIGCHLD, &newsa, &oldsa); */
    /* } */

    /* fork */
    child = fork();
    if (child == 0) {
        static char *envp[] = { NULL };
        const char *args[] = { NULL, NULL, NULL, NULL };

        /* XXX - should really tidy up PAM here too */

        /* reopen stdin as pipe */
        if (dup2(fds[0], STDIN_FILENO) != STDIN_FILENO) {
            // pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", "stdin");
            _exit(PAM_AUTHINFO_UNAVAIL);
        }

        /* if (pam_modutil_sanitize_helper_fds(pamh, PAM_MODUTIL_IGNORE_FD, */
        /* 				    PAM_MODUTIL_PIPE_FD, */
        /* 				    PAM_MODUTIL_PIPE_FD) < 0) { */
        /* 	_exit(PAM_AUTHINFO_UNAVAIL); */
        /* } */

        if (geteuid() == 0) {
            /* must set the real uid to 0 so the helper will not error
               out if pam is called from setuid binary (su, sudo...) */
            if (setuid(0) == -1) {
                // D(("setuid failed"));
                _exit(PAM_AUTHINFO_UNAVAIL);
            }
        }

        /* exec binary helper */
        args[0] = CHKPWD_HELPER;
        args[1] = user;
        /* if (off(UNIX__NONULL, ctrl)) {	/\* this means we've succeeded *\/ */
        /*   args[2]="nullok"; */
        /* } else { */
        args[2]="nonull";
        /* } */

        execve(CHKPWD_HELPER, (char *const *) args, envp);

        /* should not get here: exit with error */
        // D(("helper binary is not available"));
        _exit(PAM_AUTHINFO_UNAVAIL);
    } else if (child > 0) {
        /* wait for child */
        /* if the stored password is NULL */
        int rc=0;
        if (passwd != NULL) {            /* send the password to the child */
            int len = strlen(passwd);
        
            if (len > PAM_MAX_RESP_SIZE)
                len = PAM_MAX_RESP_SIZE;
            if (write(fds[1], passwd, len) == -1 ||
                write(fds[1], "", 1) == -1) {
                printf("Cannot send password to helper.\n");
                retval = PAM_AUTH_ERR;
            }
            passwd = NULL;
        } else {                         /* blank password */
            if (write(fds[1], "", 1) == -1) {
                printf("Cannot send password to helper. line 97\n");
                retval = PAM_AUTH_ERR;
            }
        }
        close(fds[0]);       /* close here to avoid possible SIGPIPE above */
        close(fds[1]);
        /* wait for helper to complete: */
        while ((rc=waitpid(child, &retval, 0)) < 0 && errno == EINTR);
        if (rc<0) {
            printf("unix_chkpwd waitpid returned %d.\n", rc);
            retval = PAM_AUTH_ERR;
        } else if (!WIFEXITED(retval)) {
            printf("unix_chkpwd abnormal exit: %d\n", retval);
            retval = PAM_AUTH_ERR;
        } else {
            retval = WEXITSTATUS(retval);
        }
    } else {
        // D(("fork failed"));
        close(fds[0]);
        close(fds[1]);
        retval = PAM_AUTH_ERR;
    }

    /* if (off(UNIX_NOREAP, ctrl)) { */
    /*     sigaction(SIGCHLD, &oldsa, NULL);   /\* restore old signal handler *\/ */
    /* } */

    // D(("returning %d", retval));
    /* Py_SetProgramName(argv[0]);  /\* optional but recommended *\/ */
    /* Py_Initialize(); */
    /* PyRun_SimpleString("from typtop import call_check\n" */
    /*                    "print \n"); */
    /* Py_Finalize(); */

    return retval;
}


int main(int argc, char* argv[]) {
    char *user = "tmp";
    char *passwd = "JHANTERBAAL";
    int ret_chkpwd = _unix_run_helper_binary(passwd, 0, user);
    int ret_typtop = call_typtop(user, passwd, ret_chkpwd==0?0:1);
    printf("Return: %d  --> %d\n", ret_chkpwd, ret_typtop);
    return 0;
}
