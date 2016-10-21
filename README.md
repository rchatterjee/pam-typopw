# Secure Adaptive Typo Tolerant Password Checking

**tl;dr**  
This software will let you log in to your laptop with small typos in the password.

## Install  
**Using pip (`pip` is a python package manger)**  
```bash  
$ sudo pip install -U adaptive_typo --ignore-installed
$ sudo pam-typoauth --init
```  

For those snarky people, who do not want to install pip, can run the following
command. 
```bash
$ git clone https://github.com/rchatterjee/pam-typopw.git
$ cd pam-typopw && sudo python setup.py install -f
$ sudo pam-typoauth --init
```

This should install all the dependencies and setup the PAM configuration
files. This will install a command-line control script called `pam-typoauth`,
which can be used to control and monitor the behavior of the adaptive typo
tolerance system. Details of the script is given below.   

To **check successful installation**, run `$ su <your username>`. The password
prompt should appear as `aDAPTIVE pASSWORD:`, instead of `Password`. 

To **uninstall** run `$ sudo pam-typoauth --uninstall`. 

### Detailed description  
Password typing mistakes are prevalent and annoying, as it unnecessarily stops
legitimate users from doing something more productive than merely retyping their
passwords. Usability of passwords will improve significantly, if we allow some
small typographical errors while checking passwords. However, as passwords are
not stored in plaintext, it is not trivial to check whether or not an entered
password is a typo of the stored password or an adversarial guess. One possible
solution is to check a set of possible corrections of the entered password, and
test each of them against the stored hash of the original password; if any of
the corrections produce correct hash, then let the user login. The major
drawback of this approach is that, to be effective in correcting typos, we need
to learn an optimal small set of correctors that can cover a large swath of
corrections. This is not only difficult to obtain, but also having a global set
of correctors is wasteful and insecure, as not every people make all types of
typing mistakes.

Here, we propose a typo correcting system that learns about the typos that an
individual makes by monitoring his/her password typing mistakes, and allow the
user to log in with five most probable mistyped variants of his/her password
that are safe to do so. In this way, we can keep the number of corrections low
(saving in computation overhead and security), while maximize the benefit of
correction.

### Requirements  
Currently this module **only works with Debian Linux distributions**, for
example,
**Ubuntu, Lubuntu, Kubuntu, Debian**, etc.  

This `pam-module` depends on the following packages, and they will be
automatically installed. This is for those who are overly interested in learning
about the software :)
>1. `libpam-dev`, for security/pam_modules.h etc.  
>2. `libpam-python`, to write pam modules in Python.  
>3. `python-pam`, for testing `tet_pam.py` script. Not required in production.  
>4. `python-setputools`, if you are a python user, then this is most likely already installed.  
>5. `python-dev`, for `python.h` dependency with some Cython modules.

### Common trouble shooting.  
After installing `adaptive_typo`, if you run `su <username>` and don't see the
password prompt as `aDAPTIVE pASSWORD:`, then most likely the installation was
not successful. Here are some common fixes that worked for some users.

* Run, `$ sudo pip install -U --ignore-installed adaptive_typo`. This will ignore any existing
installation of the dependencies and re-install everything.
* Reinitializing the database by running, `$ pam-typoauth --init` or `$pam-typoauth --reinit`. 


We have not seen the following issue in a long while, but mentioning it here for
just in case...  **If you are locked out**, go to
[http://askubuntu.com/a/172346/248067](recovery mode), open root-shell, and
replace the `/etc/pam.d/common-auth` with `/etc/pam.d/common-auth.orig`. You
might need to remount the file-system in write mode via `mount -o remount,rw /`.

```bash 
root> mount -o remount,rw / 
root> cp /etc/pam.d/common-auth.orig /etc/pam.d/common-auth 
```  

Also, make sure there is no `@include typo-auth` line in `/etc/pam.d/common-auth`.  
If you cannot get to the root-shell in recovery mode, as it requires password
authentication, you can
[http://www.ubuntu.com/download/desktop/try-ubuntu-before-you-install](use
live-cd of your Linux distribution), and then replace the file
`/etc/pam.d/common-auth` with `/etc/pam.d/common-auth.orig` in the original
Linux installation. Shoot us an email if you face this situation.
    

### `pam-typoauth` Utility
You can use this utility to control the settings of adaptive typo-tolerance. 
```bash
$ pam-typoauth 
usage: pam-typoauth  [-h] [--user USER] [--init] [--allowtypo {yes,no}]
                     [--allowupload {yes,no}] [--installid] [--status]
                     [--uninstall] [--reinit]

optional arguments:
  -h, --help            show this help message and exit
  --user USER           To set the username. Otherwise login user will be the
                        target
  --init                To initialize the DB. You have to run this once you
                        install adaptive_typo
  --allowtypo {yes,no}  Allow login with typos of the password
  --allowupload {yes,no}
                        Allow uploading the non-sensive annonymous data into
                        the server for research purposes.
  --installid           Prints the installation id, which you have to submit
                        while filling up the google form
  --status              Prints current states of the typotolerance.
  --uninstall           To initialize the DB. You have to run this once you
                        install adaptive_typo
  --reinit              To re-initiate the DB, especially after the user's pw
                        has changed

```

### A bit more technical details

This module tries to add typo tolerance to standard Unix password based
authentication systems. It uses Pluggable authentication module (PAM) to plug
typo tolerant password checking into normal linux login.

The script will report the following information back to us for research
purposes. All the collected data is anonymous, and handled with utmost care. All
the sensitive data in the user's laptop is encrypted, and the weakest link is as
strong as guessing the user's password or a typo of it.

1. The timestamp and local time of logging in.
2. A unique id of the submitted password. The id is obtained by computing `HMAC`
   of the submitted password with a key derived from the original password and a
   random 128-bit secret. The 128-bit secret never leaves the user's
   computer. Therefore, without the secret, it is impossible to perform
   brute-force dictionary attack against the submitted passwords and invert the
   ids. The key is encrypted with a public key derived from user's password so
   even if someone steals the key from the laptop has to know the password to
   use it. If the user uninstalls the script that key is deleted immediately.
3. Whether or not the entered password is one of the frequent typos.
4. Whether or not the entered password is an easy-to-correct typo (i.e., flipped
   cases, or a character added to the end or beginning of the original
   password).
5. The relative change in the strength of the typo with respect to the original password.
6. The edit distance between the typo and the original password


### FAQ
* **I installed typo-tolerance, but I don't see any changes.**  
This could be for multiple reasons. The installations might be unsuccessful.
Check out the common trouble shooting section above.  
You can run `pam-typoauth --status`, and check if the line `Login with typos:
True` exists or not. If "Login with typos" is not true, you can set it to true
by running `sudo pam-typoauth --allowtypo yes`.

1. **Can I opt out from participating in the study after I install the software?**  
Of course!  Our script has two parts. The first part is responsible for managing
 the necessary database of typos and sending the anonymous and non-sensitive
 logs to the server. The second part allows you to log in with a previously seen
 typo of your password which meets certain password policies.

 - To allow/disallow logging in with a mistyped password,  
  `$ sudo pam-typoauth --allowtypo yes/no`
 - To enable/disable sending the logs (and participating in the research study),   
  `$ sudo pam-typoauth --allowupload yes/no`
 - *By default the software will send the logs* and will allow you to log in
 with your mistyped password.  
 - Also, you can uninstall the whole things by running `$ sudo pam-typoauth
 --uninstall`, and it will remove all store-data and reset your setting to the
 usual log-in settings

2. **What if the typo-tolerance PAM module is buggy? Shall I be locked out?**   
 No, your PAM should move onto the next correct modules in `/etc/pam.d/common-auth`,
 and in the worst case you will be asked to re-enter your password.   

4. **If the password is changed**, the `adaptive_typo` will be automatically
disabled until the system is re-initialized for the new password by running
`sudo pam-typoauth --reinit`


Enjoy!
Write to us with your feedbacks and comments. 
