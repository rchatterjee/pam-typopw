# TypToP: Secure Adaptive __Typo-tolerant Password__ Checking

**tl;dr**
TypToP (pronounced as 'tAip-top') is a password checking scheme that
learns from your mistakes in typing login password and let you log in
to your laptop with small typos.

If you install this software and want to participate in our research
study, please fill in this
[this short survey](https://docs.google.com/forms/d/e/1FAIpQLSfHWAPedMVT7ETaW3qUUaueOg87TaDAllQYIgoqJZ8nWjF88A/viewform). Thanks!!

*For the purpose of the research study, TypTop will not allow login with typos until you login successfully 30 times.*



## Install

It require Python-2.7. All the following commands are assuming you have Python-2.7 and pip.
(`pip` is a python package manger)
```bash
$ sudo pip install -U --ignore-installed typtop && sudo typtops.py --init --user $USER
```

If `pip` is not installed you can install it as follows:
```bash
$ curl https://bootstrap.pypa.io/get-pip.py | sudo python
```
Or just `$ easy_install pip` might also work.

<!-- Install Homebrew -->
<!-- ```bash -->
<!-- $ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" -->
<!-- ``` -->
<!-- For those snarky people, who do not want to install pip, can run the following -->
<!-- command. -->
<!-- ```bash -->
<!-- $ git clone https://github.com/rchatterjee/pam-typopw.git -->
<!-- $ cd pam-typopw && sudo python setup.py install -f -->
<!-- ``` -->

This should install all the dependencies and setup the PAM configuration
files. This will install a command-line control script called `typtop`,

which can be used to control and monitor the behavior of the adaptive typo
tolerance system. Details of the script is given below.

<!-- To **check successful installation**, run `$ su <your username>`. The password
prompt should appear as `pASSWORD:`, instead of `Password`.
-->

To **uninstall** run `$ sudo typtops.py --uninstall`.

### Requirements

Currently this works in **OSX** (I tested in 10.10, 10.11, and 10.12.), and
**Linux** (tested on Ubuntu and Debian, and testing on Fedora, CentOS. **Linux
users please hold on before installing until this line is gone.** ).

#### Works in following OSs
* OSX 10.10, 10.11, 10.12
* Ubuntu 14.04+
* CentOS, RedHat

<!-- Currently this module **only works with Debian Linux distributions**, for -->
<!-- example, -->
<!-- **Ubuntu, Lubuntu, Kubuntu, Debian**, etc. -->

In OSX, this installs a modified
[pam_opendirectory](https://opensource.apple.com/source/pam\_modules/pam_modules-76/pam_opendirectory/pam_opendirectory.c)
module which calls the Typtop module on every invocation for authentication.

In Linux, it replaces the `unix_chkpwd` with a modified `unix_chkpwd` that
mimics the functionality of original `unix_chkpwd` in addition to calling
Typtop module on every invocation.

TypToP has following non-python dependencies. The Python dependencies are auto-installed while installing with pip.

1. `python-setputools`, if you are a python user, then this is most likely already installed.
2. `python-dev`, for `python.h` dependencies with some Cython modules.
3. `openssl-dev`, for cryptography.io in Linux only. The name might be different for your distribution. Please Google.
4. `libffi-dev`, for cryptography.io
5. `libpam-dev`, for pam_typtop.
5. `gcc`, obviously!! Might be best way to install it is `build-essential`.

- **CentOS**:
I had to install [gcc](https://www.cyberciti.biz/faq/centos-rhel-7-redhat-linux-install-gcc-compiler-development-tools/)
and [python-devel](http://stackoverflow.com/a/23634734/1792013)
`$ yum install python-devel`
- **Redhat**: I had to install [redhat-rpm-config](http://stackoverflow.com/a/34641068/1792013) and
[python-devel](http://stackoverflow.com/a/23634734/1792013)
`$ dnf install python-devel openssl-devel redhat-rpm-config`
- **Debian (and Ubuntu)**:
`$ apt-get install build-essential python-dev libffi-dev libssl-dev pkg-config`


### Detailed description
(*This is for those who are overly interested in learning about the software :)*)
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

Here, we propose a typo correcting system that learns about the typos made by an
individual while typing their passwords, and allows the user to log in with five
most probable mistyped variants of their password which are safe to do so. In
this way, we can keep the number of corrections low (saving in computation
overhead and security loss), while maximize the benefits of password typo correction.


<!-- ### Common trouble shooting

After installing `typtop`, if you run `su <username>` and don't see the password
prompt as `pASSWORD:`, then most likely the installation was not
successful. Here are some common fixes that worked for some users.

Run, `$ sudo pip install -U --ignore-installed typtop && sudo typtops.py
--init`. This will ignore any existing installation of the dependencies and
re-install everything.
-->

<!-- We have not seen the following issue in a long while, but mentioning it here for -->
<!-- just in case...  **If you are locked out**, go to -->
<!-- [recovery mode](http://askubuntu.com/a/172346/248067), open root-shell, and -->
<!-- replace the `/etc/pam.d/common-auth` with `/etc/pam.d/common-auth.orig`. You -->
<!-- might need to remount the file-system in write mode via `mount -o remount,rw /`. -->

<!-- ```bash -->
<!-- root> mount -o remount,rw / -->
<!-- root> cp /etc/pam.d/common-auth.orig /etc/pam.d/common-auth -->
<!-- ``` -->

<!-- Also, make sure there is no `@include typo-auth` line in -->
<!-- `/etc/pam.d/common-auth`.  If you cannot get to the root-shell in recovery mode, -->
<!-- as it might require password authentication, you can -->
<!-- [use live-cd of your Linux distribution](http://www.ubuntu.com/download/desktop/try-ubuntu-before-you-install), -->
<!-- and then replace the file `/etc/pam.d/common-auth` with -->
<!-- `/etc/pam.d/common-auth.orig` in the original Linux installation. Shoot us an -->
<!-- email if you face this situation. -->


### `typtop` Utility

_In Linux we have `typtops.py` instead of `typtop`, and one will need root permission to run the script_.

You can use this utility to control the settings of adaptive
typo-tolerance.  *We are working on cleaning this utility and making it easier to use.*

```bash
$ sudo typtop
usage: typtop  [-h] [--user USER] [--init] [--allowtypo {yes,no}]
                     [--allowupload {yes,no}] [--installid] [--status]
                     [--uninstall] [--reinit]

optional arguments:
  -h, --help            show this help message and exit
  --user USER           To set the username. Otherwise login user will be the
                        target
  --init                To initialize the DB. You have to run this once you
                        install pam_typtop
  --allowtypo {yes,no}  Allow login with typos of the password
  --allowupload {yes,no}
                        Allow uploading the non-sensive annonymous data into
                        the server for research purposes.
  --installid           Prints the installation id, which you have to submit
                        while filling up the google form
  --status  $USER       Prints current states of the typotolerance.
  --uninstall           To initialize the DB. You have to run this once you
                        install pam_typtop
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
1. **I installed typo-tolerance, but I don't see any changes.**
   This could be for multiple reasons. The installations might be unsuccessful.
   <!--Check out the common trouble shooting section above.-->
   You can run `typtop --status $USER`, and check if the line `Login with typos:
   True` exists or not. If "Login with typos" is not true, you can set it to true
   by running `sudo typtop --allowtypo yes`.

2. **Can I opt out from participating in the study after I install the software?**
 Of course!  Our script has two parts. The first part is responsible for managing
 the necessary database of typos and sending the anonymous and non-sensitive
 logs to the server. The second part allows you to log in with a previously seen
 typo of your password which meets certain password policies.
   * To allow/disallow logging in with a mistyped password,
    `$ sudo typtop --allowtypo yes/no`
   * To enable/disable sending the logs (and participating in the research study),
    `$ sudo typtop --allowupload yes/no`
   * *By default the software will send the logs* and will allow you to log in
   with your mistyped password.
   * Also, you can uninstall the whole things by running `$ sudo typtop
   --uninstall`, and it will remove all store-data and reset your setting to the
   usual log-in settings

3. **What if the typo-tolerance PAM module is buggy? Shall I be locked out?**
   No, your PAM should move onto the next correct modules in `/etc/pam.d/common-auth`,
   and in the worst case you will be asked to re-enter your password.

4. **If the password is changed**, the `pam_typtop` will be automatically
   disabled until the system is re-initialized for the new password by running
   `sudo typtop --reinit`


### TODO


Enjoy!  Write to us with your feedbacks and comments.
