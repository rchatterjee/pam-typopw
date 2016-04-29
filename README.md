## pam-typopw

This module tries to add typo tolerance to standard Unix password
based authentication systems. It uses Pluggable authentication module
(PAM) to plug typo tolerant password checking into services for which
the users wishes to avail the benefit, such as, normal login. 

I am still wokring on figuring out the details. 

### Requirements

Assuming you have `make` and `gcc`, additionally you have to
install the following libraries, 
    >1. `libpam0g-dev`, for security/pam_modules.h etc.
	>2. `libpam-python`, to write pam modules in Python. (Trust me much easier than C!)

Both of these can be installed using standard `apt-get`. (Though not
sure about non-debian world.)

### How to? 
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

#### Issues
To implement `mistypography` you have to install pwmodels, and make a symlink of `pwmodels/pwmodel/helper.py` in the `typofixer/` folder
