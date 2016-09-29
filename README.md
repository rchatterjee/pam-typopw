## pam-typopw / Adaptive typo tolerance

Login failure due to small mistakes in the login password is annoying for legitimate users. Allowing small typographical errors while checking password can improve usability significantly. However, making too many corrections could degrade security drastically, and be computationally expensive. Here, we propose a typo correcting system that is built specifically for your mistakes. We believe users make only a few different types of typos, so, we can keep the number of corrections low (saving in computation overhead and security), while maximize the benefit of correction. We need to verify our hypothesis, and hence this project.

### A bit more technical details

This module tries to add typo tolerance to standard Unix password based
authentication systems. It uses Pluggable authentication module (PAM) to plug
typo tolerant password checking into normal linux login.

The script will report the following information back to us for research purposes. All the collected data are anonymous, and handled with utmost care. All the sensitive data in the user's laptop is encrypted, and the weakest link is as strong as guessing the user's password. 
>1. The timestamp and local time of logging in.
>2. A unique id of the submitted password. The id is obtained by computing HMAC of the submitted password with a key derived from the original password and a random 128-bit secret. The 128-bit secret never leaves the user's computer. Therefore, without the secret, it is impossible to perform brute-force dictionary attack against the submitted passwords and invert the ids. If the user uninstalls the script that key is deleted immediately 
>3. Whether or not the entered password is one of the frequent typos.
>4. Whether or not the entered password is an easy-to-correct typo (i.e., flipped cases, or a character added to the end or beginning of the original password).
>5. The relative change in the strength of the typo with respect to the original password.
>6. The edit distance between the typo and the original password

**Right now this only supports Debian distributions.
In the future we might port this project to Fedora, CetOS, MAC and Windows**


### Requirements  
Assuming you have `make` and `gcc`. All of the following are dependencies, which
will be installed automatically by the `install.sh` script.

>1. `libpam-dev`, for security/pam_modules.h etc.
>2. `libpam-python`, to write pam modules in Python.
>3. `python-pam`, for testing `tet_pam.py` script. Not required in production.
>4. `python-setputools`, if you are a python user, then this is most likely already isntalled. 
>5. `python-dev`, for `python.h` dependency with some cypthon modules.

-->
### Install
```bash
$ git clone https://github.com/rchatterjee/pam-typopw.git && cd pam-typopw && sudo python setup.py install
```

This should install all the depenedencies and setup the PAM config files. This
will install a command-line control script `pam-typoauth` which you can use to
control and monitor the behaivior of the adaptive typo tolernace system. Details
of the script is given below.  

To **uninstall** run `pam-typoauth --uninstall` (requires root priviledges).

### If the user change his password
When the user changes his password, the adaptive typo will be disabled until the system is re-initialized for the new password
*****ADD more details about using the settings ******

### FAQ
* **Can I opt out after I've entered this project?**
Our script has two parts, one which is responsible to manage the necessary data and send it securely to us, and the other which allows you to enter with a close, given before, typo of your password. Both of these part can be disabled
*****ADD more details about using the settings ******

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
