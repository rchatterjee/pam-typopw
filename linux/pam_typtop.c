#define _XOPEN_SOURCE 700

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "Linux-PAM-1.2.1-typtop/modules/pam_unix/support.h"
#include <syslog.h>
#include <python2.7/Python.h>

const int TYPTOP_COLLECT = 1;
const int TYPTOP_FIN = 2;



static int
call_typtop(pam_handle_t *pamh, const char* user, const char* passwd, int chkwd_ret) {
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
                pam_syslog(pamh, LOG_NOTICE, "Result of call: %ld\n", PyInt_AsLong(pValue));
                int ret = PyInt_AsLong(pValue);
                Py_DECREF(pValue);
                return ret;
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                pam_syslog(pamh, LOG_CRIT, "Call to typtop binary failed.\n");
                return 1;
            }
        }
        else {
            if (PyErr_Occurred())
                PyErr_Print();
            pam_syslog(pamh, LOG_CRIT, "Cannot find function \"%s\"\n", "call_check");
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        pam_syslog(pamh, LOG_CRIT, "Failed to load \"%s\"\n", "typtop.dbaccess");
        return 1;
    }
    Py_Finalize();
    return 1;
}

/*  Runs TypToP, fetching the entered password using `pam_get_authtok`
    If 
*/
__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int correct_pw = 0;
    int retval;
    const char *name;
    const char *passwd;

    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "incorrect_pass")) {
            correct_pw = 1;
        }
    }

    if (correct_pw == 0) {
        pam_syslog(pamh, LOG_NOTICE, "user entered the correct pw!");
    } else {
        pam_syslog(pamh, LOG_NOTICE, "incorrect password entered");
    }

    if (pam_get_user(pamh, &name, NULL) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "couldn't get username from PAM stack");
        return PAM_USER_UNKNOWN;
    } else {
        pam_syslog(pamh, LOG_NOTICE, "username correctly identified");
    }


    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &passwd, "this shouldn't be displayed... try entering a password");
    if (retval != PAM_SUCCESS || passwd == NULL){
        pam_syslog(pamh, LOG_WARNING, "couldn't find cached password or password is blank");
        return PAM_IGNORE;
    } else {
        retval = call_typtop(pamh, name, passwd, correct_pw);
        if (retval == 0){
            if (correct_pw == 0) {
                pam_syslog(pamh, LOG_NOTICE, "called typtop with correct pw");
            } else {
                pam_syslog(pamh, LOG_NOTICE, "typtop allowed typo-ed password");
            }
            return PAM_SUCCESS;
        } else {
            pam_syslog(pamh, LOG_NOTICE, "typtop either failed or check did not pass");
            return PAM_AUTH_ERR;
        }
    }
}


__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags,
        int argc, const char **argv)
{
    return PAM_SUCCESS;
}
