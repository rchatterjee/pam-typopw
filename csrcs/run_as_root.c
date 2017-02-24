#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __APPLE__
#  include <security/_pam_macros.h>
#else
#  include <security/pam_appl.h>
#endif

#include <syslog.h>
#include <python2.7/Python.h>

#define MAX_PASSWD_LEN 1024

static int
call_typtop(const char* user, const char* passwd, int chkwd_ret) {

    Py_Initialize();
    int ret = 1;
    PyObject *pModule, *pName, *pFunc;
    PyObject *pArgs, *pValue;

    /* char *path, *newpath; */
    /* // /usr/local/lib might not be in python path  */
    /* path = Py_GetPath(); */
    /* newpath = (char*)malloc(sizeof(char) * (strlen(path) + 40)); */
    /* char sep = ':'; // in linux and windows this is different */
    /* if (!strchr(path, sep)) sep = ';'; */
    /* sprintf(newpath, "%s%c/usr/local/lib/python2.7/dist-packages", path, sep); */
    /* printf("newpath = %s\n", newpath); */
    /* syslog(LOG_NOTICE, "newpath=%s\n", newpath); */
    /* PySys_SetPath(newpath); */

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
                ret = PyInt_AsLong(pValue);
                Py_DECREF(pValue);
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                syslog(LOG_CRIT, "Call to typtop binary failed.\n");
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
    }
    Py_Finalize();
    // free(newpath);
    return ret;
}


int main(int argc, char* argv[]) {
    // openlog("auth.log",
    if (seteuid(0) != 0 || setuid(0) != 0) {
        syslog(LOG_CRIT, "Failed to run as root.");
    }
    Py_SetProgramName(argv[0]);

    if (argc==4 && strcmp(argv[1], "--check")==0) {
        int chkpw_ret = atoi(argv[2]);
        char *user = argv[3];
        // char *pass = argv[3];
        char ch, pass[MAX_PASSWD_LEN+1];
        int pass_i = 0;
        while(scanf("%c", &ch) > 0) {
          pass[pass_i++] = ch;
          if (pass_i >= MAX_PASSWD_LEN)
            break;
          if (pass[pass_i-1] == '\n' || pass[pass_i-1] == '\r') {
            pass_i --; // "\n" is not allowed in your password!!
            break;
          }
        }
        pass[pass_i] = '\0';

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
