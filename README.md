## pam-typopw

This module tries to add typo tolerance to standard Unix password based
authentication systems. It uses Pluggable authentication module (PAM) to plug
typo tolerant password checking into normal linux login.

**Right now this only supports Debian distributions. We are working on porting
this project to Fedora, CetOS, MAC and Windows**


### Requirements  
Assuming you have `make` and `gcc`. All of the following are dependencies, which
will be installed automatically by the `install.sh` script.

>1. `libpam-dev`, for security/pam_modules.h etc.
>2. `libpam-python`, to write pam modules in Python.
>3. `python-pam`, for testing `tet_pam.py` script. Not required in production.
>4. `python-setputools`, if you are a python user, then this is most likely already isntalled. 
>5. `python-dev`, for `python.h` dependency with some cypthon modules.


<!--### How to? 
We have two implementation of this module--one in C and another in 
Python2.7. I shall explain them below in order.
 
#### C implementation
Compile the pam_module by running, `make`. If the compilation runs
good, you should get a shared library file named "pam_pwtypo.so".  We
shall explain how to add this pam module into action. First, lets do a
test run. 
```bash
$ sudo echo "auth requisite ${pwd}/pam_pwrypo.so" > /etc/pam.d/test 
$ python test_pam.py
```

If it asks for your login credentials, then you have correct
compilation of the `pam_pwtypo.so` module. Now, you just have to add
the line that you put inside `/etc/pam.d/test` file to the service
files (found in /etc/pam.d) where you wish to use typo tolerance. Add
the line before `pam_unix`.


#### Python implementation
-->
#### Install
Run `install.sh` to install. This will require super user permission.
```bash
$ sudo bash install.sh
```

This should install all the depenedencies and setup the PAM config
files. Use `uninstall.sh` to uninstall the program (require root
priviledges).


* **What if the typo-tolerance PAM module is buggy? Shall I be locked out?**   
No, your PAM should move onto next correct modules in common-auth, and you will be asked to re-enter your credentials.   

* **In case if you are locked out**, go to recovery mode, open root shell, and replace the `/etc/pam.d/common-auth` with 
`/etc/pam.d/common-auth.orig`. You might need to remount the file-system in write mode via `mount -o remount,rw /`.
```bash
root> mount -o remount,rw /
root> cp /etc/pam.d/common-auth.orig /etc/pam.d/common-auth
```
Also, make sure there is no `@include typo-auth` line in `/etc/pam.d/common-auth`.



Enjoy!


### TODO:
1. Found the bug for "No child
process". /usr/lib/python2.7/ctypes/util.py:240 has os.popen, which is
buggy. replacing that with subprocess.Popen(...).wait() works
fine. Need to file a bug with ctypes or find some solution.

2. After first failure, pam moves to the next module, which is bad.
