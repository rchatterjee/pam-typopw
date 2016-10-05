## pam-typopw / Adaptive typo tolerance

Password typing mistakes are prevalent and annoying as it unnecessarily stops legimate users from doing something more productive than merely retyping their passwords. Usability of passwords will imrpove significantly, if we allow some small typographical errors while checking passwords. As passwords are not stored in plaintext, it is not trivial to check whether or not an entered password is a typo or an adversarial guess. One possible solution to that is to check a set of possible corrections of the entered password. However this requires learning proper set of corrections, or in a way the distributions of typographical errors. Here, we propose a typo correcting system that is built specifically for your mistakes, that is, the system monitors your password typing mistakes and allow you to log in with five most probable mistyped version of your passwod. We believe users make only a few different types of typos over and over again, so, we can keep the number of corrections low (saving in computation overhead and security), while maximize the benefit of correction.

### A bit more technical details

This module tries to add typo tolerance to standard Unix password based
authentication systems. It uses Pluggable authentication module (PAM) to plug
typo tolerant password checking into normal linux login.

The script will report the following information back to us for research purposes. All the collected data are anonymous, and handled with utmost care. All the sensitive data in the user's laptop is encrypted, and the weakest link is as strong as guessing the user's password.

1. The timestamp and local time of logging in.
2. A unique id of the submitted password. The id is obtained by computing HMAC of the submitted password with a key derived from the original password and a random 128-bit secret. The 128-bit secret never leaves the user's computer. Therefore, without the secret, it is impossible to perform brute-force dictionary attack against the submitted passwords and invert the ids. If the user uninstalls the script that key is deleted immediately 
3. Whether or not the entered password is one of the frequent typos.
4. Whether or not the entered password is an easy-to-correct typo (i.e., flipped cases, or a character added to the end or beginning of the original password).
5. The relative change in the strength of the typo with respect to the original password.
6. The edit distance between the typo and the original password


### Requirements  
This module **only works with Debian linux distros**, for example, **Ubuntu, Lubuntu, Kubuntu, Debian**, etc.  

This pam_module depends on the following packages. These will be installed automatically once you call
`python setup.py install`.  **Do not use pip to install this pam_module**.
>1. `libpam-dev`, for security/pam_modules.h etc.
>2. `libpam-python`, to write pam modules in Python.
>3. `python-pam`, for testing `tet_pam.py` script. Not required in production.
>4. `python-setputools`, if you are a python user, then this is most likely already isntalled. 
>5. `python-dev`, for `python.h` dependency with some cypthon modules.


### Install

```bash
$ git clone https://github.com/rchatterjee/pam-typopw.git
$ cd pam-typopw && sudo python setup.py install
```

This should install all the depenedencies and setup the PAM config files. This
will install a command-line control script `pam-typoauth` which you can use to
control and monitor the behaivior of the adaptive typo tolernace system. Details
of the script is given below.  

To **uninstall** run `pam-typoauth --uninstall` (requires root priviledges).

### `pam-typoauth` Utility
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

### If the user change his password
When the user changes his password, the adaptive typo will be disabled until the system is re-initialized for the new password
In order to re-initiate the typo-tolerance, run `sudo pam-typoauth --reinit`

### FAQ
* **I installed typo-tolerance, but I don't see any changes.**
The initial script's state doesn't allow logining in a typo. Initially it just stores the necessery data for it to work once you enable it.
In order to allow the logging-in, run
>> `sudo pam-typoauth --allowtypo yes`

* **Can I opt out after I've entered this project?**
Of course!
Our script has two parts, one which is responsible to manage the necessary data and send it *securely* to us, and the other which allows you to enter with a close, given before, typo of your password. Both of these part can be disabled
- To disallow logging in with a typo, run 
 `sudo pam-typoauth --allowtypo no`
- To allow logging in with a typo, run
 `sudo pam-typoauth --allowtypo yes`
- To disable the sending of logs, run
 `sudo pam-typoauth --allowupload no`
- To enable the sending of logs, run
 `sudo pam-typoauth --allowupload yes`

Also, you can uninstall the whole things by running `sudo bash ~/pam-typopw/uninstall.sh `, and it will remove all store-data and reset your setting to the usual log-in settings

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
