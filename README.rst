TypToP: Secure Adaptive **Typo-tolerant Password** Checking
===========================================================

**tl;dr** TypToP (pronounced as 'tAip-top') is a password checking
scheme that learns from your mistakes in typing login password and let
you log in to your laptop with small typos.

If you install this software and want to participate in our research
study, please fill in this `this short
survey <https://docs.google.com/forms/d/e/1FAIpQLSfHWAPedMVT7ETaW3qUUaueOg87TaDAllQYIgoqJZ8nWjF88A/viewform>`__.
Thanks!!

.. raw:: html

   <!-- *For the purpose of the research study, TypTop might not allow login with typos
   until you login successfully 30 times.* -->


Install
-------

It requires Python-2.7 and some more depending on your OS, check the
`Requirements Section <#requirements>`__. #### Works in following OSs \*
OSX 10.9+ \* Most of Linux distros (Tested in Ubuntu 14.04+, CentOS,
RedHat, Arch.)

.. code:: bash

    # If you don't have pip, install it using the following command.
    $ curl https://bootstrap.pypa.io/get-pip.py | sudo python2.7  # use 'wget -O -' if you don't have 'curl' 
    $ sudo pip install -U --ignore-installed typtop && sudo typtops.py --init

To **uninstall** run ``$ sudo typtops.py --uninstall``.

.. raw:: html

   <!-- To checkout the test version: -->
   <!-- ```bash -->
   <!-- $ sudo -H pip install --ignore-installed -U --extra-index-url https://testpypi.python.org/pypi typtop && sudo typtops.py --init -->
   <!-- ``` -->
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

   <!-- This should setup the PAM configuration files. This will install a
   command-line control script called `typtop`,

   which can be used to control and monitor the behavior of the adaptive typo
   tolerance system. Details of the script is given below. -->

   <!-- To **check successful installation**, run `$ su <your username>`. The password
   prompt should appear as `pASSWORD:`, instead of `Password`.
   -->

 Requirements
~~~~~~~~~~~~~

.. raw:: html

   <!-- Currently this module **only works with Debian Linux distributions**, for -->
   <!-- example, -->
   <!-- **Ubuntu, Lubuntu, Kubuntu, Debian**, etc. -->

TypToP has following non-python dependencies requird **only for Linux**.
The Pythonic dependencies are auto-installed while installing with pip.

1. ``python-setputools``, if you are a python user, then this is most
   likely already installed.
2. ``python-dev``, for ``python.h`` dependencies with some Cython
   modules.
3. ``openssl-dev`` or ``libssl-dev``, for cryptography.io (only in Linux
   only). The name might be different for your distribution. Please
   Google.
4. ``libffi-dev``, for cryptography.io.
5. ``libpam-dev``, for pam\_typtop.
6. ``gcc``, obviously!! Might be best way to install it is
   ``build-essential``.
7. ``cronie``, and ``wget`` for Arch Linux.

-  **CentOS**: I had to install
   `gcc <https://www.cyberciti.biz/faq/centos-rhel-7-redhat-linux-install-gcc-compiler-development-tools/>`__
   and `python-devel <http://stackoverflow.com/a/23634734/1792013>`__
   ``$ yum install python-devel gcc python-devel openssl-devel``

-  **Redhat**: I had to install
   `redhat-rpm-config <http://stackoverflow.com/a/34641068/1792013>`__
   and `python-devel <http://stackoverflow.com/a/23634734/1792013>`__
   ``$ dnf install python-devel openssl-devel redhat-rpm-config``

-  **Debian (and Ubuntu)**:
   ``$ apt-get install build-essential python-dev libffi-dev libssl-dev pkg-config``

-  **Arch** ``$ pacman -S python-devel cronie wget``

Detailed description
~~~~~~~~~~~~~~~~~~~~

| (*This is for those who are overly interested in learning about the
software :)*)
| Password typing mistakes are prevalent and annoying, as it
unnecessarily stops legitimate users from doing something more
productive than merely retyping their passwords. Usability of passwords
will improve significantly, if some small typographical errors are
allowed while checking passwords. However, as passwords are not stored
in plaintext, it is not trivial to check whether or not an entered
password is a typo of the stored password or an adversarial guess. One
possible solution is to check a set of possible corrections of the
entered password, and test each of them against the stored hash of the
original password; if any of the corrections produce correct hash, then
let the user login. The major drawback of this approach is that, to be
effective in correcting typos, we need to learn an optimal small set of
correctors that can cover a large swath of corrections. This is not only
difficult to obtain, but also having a global set of correctors is
wasteful and insecure, as not every people make all types of typing
mistakes.

Here, we propose a typo correcting system that learns about the typos
made by an individual while typing their passwords, and allows the user
to log in with five most probable mistyped variants of their password
which are safe to do so. In this way, we can keep the number of
corrections low (saving in computation overhead and security loss),
while maximizing the benefits of password typo correction.

In OSX, this installs a modified
`pam\_opendirectory <https://opensource.apple.com/source/pam_modules/pam_modules-76/pam_opendirectory/pam_opendirectory.c>`__
module which calls the Typtop module on every invocation for
authentication for ``su`` and ``screensaver``. Note, ``sudo`` is not
modified, so if (for some reason) TypTop fails, you can just change the
``/etc/pam.d/su`` and ``/etc/pam.d/screensaver`` file.

In Linux, ``pam_unix`` is primary module for authentication. Typtop
creates a PAM module named ``pam_typtop.so`` and modify the pam config
files in way such that whenever ``pam_unix`` is called for
authentication the control is next passed on to ``pam_typtop.so``. In
Linux all binaries (su, sudo, login etc.) are modified to use
pam\_typtop.so, however, even if TypTop crashes the applications will
function properly, only with a error message about pam\_typtop.

.. raw:: html

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

``typtop`` Utility
~~~~~~~~~~~~~~~~~~

This runs with ``shadow`` group's permission, which is not technically
``root``, but close. You can use this utility to control the settings of
adaptive typo-tolerance. *We are working on cleaning this utility and
making it easier to use.*

.. code:: bash

    $ typtop
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

What data we collect
~~~~~~~~~~~~~~~~~~~~

This module tries to add typo tolerance to standard Unix password based
authentication systems. It uses Pluggable authentication module (PAM) to
plug typo tolerant password checking into normal linux login.

The script will report the following information back to us for research
purposes. All the collected data is anonymous, and handled with utmost
care. All the sensitive data in the user's laptop is encrypted, and the
weakest link in the whole system is as strong as the user's correct
password or typos of it. It's important to note not all typos are
accepted as safe, and the system will allow only the typos which are
very "close" to the original password.

1. The timestamp and local time of logging in.
2. A unique id of the submitted password. The id is obtained by
   computing ``HMAC`` of the submitted password with a key derived from
   the original password and a random 128-bit secret. The 128-bit secret
   never leaves the user's computer. Therefore, without the secret, it
   is impossible to perform brute-force dictionary attack against the
   submitted passwords and invert the ids. The key is encrypted with a
   public key derived from user's password so even if someone steals the
   key from the laptop has to know the password to use it. If the user
   uninstalls the script that key is deleted immediately.
3. Whether or not the entered password is one of the frequent typos.
4. Whether or not the entered password is an easy-to-correct typo (i.e.,
   flipped cases, or a character added to the end or beginning of the
   original password).
5. The relative change in the strength of the typo with respect to the
   original password.
6. The edit distance between the typo and the original password

FAQ
~~~

1. **I installed typo-tolerance, but I don't see any changes.** Don't
   panic, Typtop works silently. Try to check the
   ``/var/log/typtop.log``, if it is getting updated with every
   invocation of ``su`` or ``sudo``, then it is working.

   If not, then there is something to worry about. This could be due to
   multiple reasons. The installations might be unsuccessful. You can
   run ``typtop --status $USER``, and check if the line
   ``Login with typos:    True`` exists or not. If "Login with typos" is
   not true, you can set it to true by running
   ``sudo typtop --allowtypo yes``.

2. **Can I opt out from participating in the study after I install the
   software?** Of course! Our script has two parts. The first part is
   responsible for managing the necessary database of typos and sending
   the anonymous and non-sensitive logs to the server. The second part
   allows you to log in with a previously seen typo of your password
   which meets certain password policies.

-  To allow/disallow logging in with a mistyped password,
   ``$ sudo typtop --allowtypo yes/no``
-  To enable/disable sending the logs (and participating in the research
   study), ``$ sudo typtop --allowupload yes/no``
-  *By default the software will send the logs* and will allow you to
   log in with your mistyped password.
-  Also, you can uninstall the whole things by running
   ``$ sudo typtop    --uninstall``, and it will remove all store-data
   and reset your setting to the usual log-in settings

3. **What if the typo-tolerance PAM module is buggy? Shall I be locked
   out?** We took lot of effort in ensuring that the pam no one is
   locked out due to PAM. But in case you are locked out, the option is
   to go to recover mode and be droped to a recover shell, or boot with
   a usb drive, and reset the password.

4. **If the password is changed**, the ``pam_typtop`` will automatically
   updates itself after couple of right new password entry.

TODO
~~~~

Enjoy! Write to us with your feedbacks and comments.
