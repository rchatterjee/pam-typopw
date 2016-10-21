
from __future__ import print_function
import os
import sys
from subprocess import Popen, call, PIPE
from setuptools import setup
from setuptools.command.install import install
from adaptive_typo import VERSION

GITHUB_URL = 'https://github.com/rchatterjee/pam-typopw' # URL in github repo
BINDIR = '/usr/local/bin'
SEC_DB_PATH = '/etc/adaptive_typo'
SCRIPTS = [
    'pam_typotolerant.py', 'send_typo_log.py',
    'uninstall_adaptive_typo.sh', 'adaptypo'
]
LIB_DEPENDENCIES = ['libpam-python', 'python-pam',
                    'python-setuptools', 'python-dev']
first_msg = """\n\n\n
----------------------------------------------------------------------
    / \   __| | __ _ _ __ | |_(_)_   _____  |_   _|   _ _ __   ___  
   / _ \ / _` |/ _` | '_ \| __| \ \ / / _ \   | || | | | '_ \ / _ \ 
  / ___ \ (_| | (_| | |_) | |_| |\ V /  __/   | || |_| | |_) | (_) | 
 /_/   \_\__,_|\__,_| .__/ \__|_| \_/ \___|   |_| \__, | .__/ \___/ 
                    |_|                           |___/|_| 
---------------------------------------------------------------------\n
Hello!

Thanks for installing Adaptive Typo Tolerance (version: {version}).
This software attaches a new Pluggable Authentication Module (PAM) to
almost all of your common authentication processes, and observes your
password typing mistakes. It learns about your frequent typing
mistakes, and enable logging in with popular slight vairations of your
actual login password that are safe to do so.

We would like to collect some anonymous non-sensitive data about your
password typing patterns for purely research purposes. The details of
what we collect, how we collect and store, and the security blueprint
of this software can be found in the GitHub page: {url}.
The participation in the study is completely voluntary, and you can
opt out at any time while still keep using the software.

You have to install this for each user who intend to use the benefit
of adaptive typo-tolerant password login.

Please run the following command in the terminal and follow the
instructions to initialize the typo database.

$ sudo adaptypo --init
""".format


class CustomInstaller(install):
    """
    It's a custom installer class, subclass of install.
    """
    def run(self):
        assert os.getuid() == 0, \
            "You need root priviledge to run the installation"
        if not os.path.exists(BINDIR):
            os.makedirs(path=BINDIR, mode=0755) # drwxr-xr-x
        call(['apt-get', 'install', '-y'] + LIB_DEPENDENCIES)
        call(['gcc', 'chkpw.c', '-o', '{}/chkpw'.format(BINDIR), '-lcrypt'])
        # Assuming there is a unix_chkpwd
        chkpw_proc = Popen('which unix_chkpwd'.split(), stdout=PIPE)
        unix_chkpwd = chkpw_proc.stdout.read().strip()
        chkpw_proc.wait()
        unix_chkpwd_st = os.stat(unix_chkpwd)
        os.chown(
            '{}/chkpw'.format(BINDIR), 
            unix_chkpwd_st.st_uid, 
            unix_chkpwd_st.st_gid
        )
        os.chmod('{}/chkpw'.format(BINDIR), 0o2755)

        Popen('cp -vf {} {}/'.format(' '.join(SCRIPTS), BINDIR).split()).wait()
        common_auth = '/etc/pam.d/common-auth'
        common_auth_orig = '/etc/pam.d/common-auth.orig'
        with open('/etc/pam.d/typo_auth', 'wb') as f:
            f.write(
                "auth  sufficient  pam_python.so  {}/pam_typotolerant.py\n"\
                .format(BINDIR)
            )
        if os.path.exists(common_auth_orig):
            print("Looks like you have an old installation of typo_auth."\
                  "Removing it.")
            os.rename(common_auth_orig, common_auth)
        with open(common_auth_orig, 'wb') as f:
            f.write(open(common_auth).read())
        with open(common_auth, 'w') as f:
            f.write('# for allowing typo tolerant login\n'
                    '@include typo_auth\n')
            f.write(open(common_auth_orig).read())
        # install.run(self) # this ignores all install_requires
        self.do_egg_install()
        print(first_msg(url=GITHUB_URL, version=VERSION), file=sys.stderr)
        # initiate_typodb() # Because pip install is non-interactive


# With the help from http://peterdowns.com/posts/first-time-with-pypi.html
setup(
    name='adaptive_typo', # 'loginwitherror',
    packages=['adaptive_typo'], # this must be the same as the name above
    version=VERSION,
    description='Adaptive Typo Tolerance for Debian logins',
    author='Rahul Chatterjee, Yuval Pnueli',
    author_email='rc737@cornell.edu',
    url=GITHUB_URL,
    download_url='{}/tarball/{}'.format(GITHUB_URL, VERSION),
    keywords=[
        'Password', 'typo-tolerance',
        'login-with-errors', 'Login'
    ],
    package_data={'': ['chkpw.c', 'LICENSE', 'README.md']},
    include_package_data=True,
    classifiers=['Development Status :: 4 - Beta'],
    install_requires=[
        'pycryptodome',
        'word2keypress',
        'dataset',
        'zxcvbn',
        'requests'
    ],
    cmdclass={'install': CustomInstaller},
    zip_safe=False
)
