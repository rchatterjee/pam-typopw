#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/_pam_macros.h>
#include <syslog.h>
#include <python2.7/Python.h>

static int
call_typtop(const char* user, const char* passwd, int chkwd_ret) {
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
                syslog(LOG_NOTICE, "Result of call: %ld\n", PyInt_AsLong(pValue));
                int ret = PyInt_AsLong(pValue);
                Py_DECREF(pValue);
                return ret;
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                syslog(LOG_CRIT, "Call to typtop binary failed.\n");
                return 1;
            }
        }
        else {
            if (PyErr_Occurred())
                PyErr_Print();
            syslog(LOG_CRIT, "Cannot find function \"%s\"\n", "call_check");
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        syslog(LOG_CRIT, "Failed to load \"%s\"\n", "typtop.dbaccess");
        return 1;
    }
    Py_Finalize();
    return 1;
}


int main(int argc, char* argv[]) {
    // openlog("auth.log", 
    if (seteuid(0) != 0 || setuid(0) != 0) {
        syslog(LOG_CRIT, "Failed to run as root.");
    }

    if (argc==5 && strcmp(argv[1], "--check")==0) { 
        char *user = argv[2];
        char *pass = argv[3];
        int chkpw_ret = atoi(argv[4]);
        int retval = call_typtop(user, pass, chkpw_ret);
        printf("%d", retval);
        return retval;
    } else {
        char **args = (char**)malloc(sizeof(char*)*(argc+1));
        int i;
        const char* cmd = "/usr/local/bin/typtops.py";
        args[0] = (char*)malloc(sizeof(char)*(strlen(cmd)+1));
        strcpy(args[0], cmd);
        for(i=1; i<argc; i++) {
            args[i] = (char*)malloc(sizeof(char)*(strlen(argv[i])+1));
            strcpy(args[i], argv[i]);
        }
        args[argc] = NULL;
        printf("Calling execvev -- %s", argv[0]);
        if(execv(cmd, args)<0) {
            printf(" failed for some reason.\n");
        }
    }
    return -1;   // should not reach here
}
