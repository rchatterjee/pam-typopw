import os
from adaptive_typo.typo_db_access import UserTypoDB
from pam_typotolerant import check_pw
import getpass
import pwd
from setuptools import setup
from setuptools.command.install import install
from subprocess import Popen, call, PIPE
import stat
VERSION = "0.1"
GITHUB_URL = 'https://github.com/rchatterjee/pam-typopw' # URL in github repo
BINDIR = '/usr/local/bin'
SEC_DB_PATH = '/etc/adaptive_typo'
SCRIPTS = [
    'pam_typotolerant.py', 'adaptive_typo/send_typo_log.py',
]
LIB_DEPENDENCIES = ['libpam-python', 'python-pam', 
                    'python-setuptools', 'python-dev']

first_msg = """\n\n\n
--------------------------------------------------------------------\n
Hello!

Thanks for installing Adaptive Typo Tolerance (version: {version}).
This software attaches a new Pluggable Authentication Module (PAM) to
almost all of your common authentication processes, and observes your
password typing mistakes. Eventually this learns about your frequent
typing mistakes, and enable logging in with slight but popular
vairation of your actual login password. 

We would like to collect some anonymous non-sensitive data about your
password typing patterns for purely research purposes. The details of
what we collect, how we collect and store, and the security blueprint
of this software can be found in the GitHub page (probably {url}).
The participation in the study is completely voluntary, and you can
opt out at any time while still keep using the software.

You have to install this for each user who intend to use the benefit
of adaptive typo-tolerant password login.
""".format

def initiate_typodb():
    print(first_msg(url=GITHUB_URL, version=VERSION))
    user = raw_input("Please enter your username: ")
    try:
        # checks that such a user exists:
        homedir = pwd.getpwnam(user).pw_dir
    except KeyError as e:
        print "Error: {}".format(e.message)
    else:
        right_pw = False
        for tries in range(3):
            pw = getpass.getpass()
            right_pw = (check_pw(user, pw) == 0)
            if right_pw:
                print("Initiating the database...",)
                tb = UserTypoDB(user)
                tb.init_typotoler(pw)
                print("Done!")
                return 0
            else:
                print("Doesn't look like a correct password. Please try again.")

        print "Failed to enter a correct password 3 times."
        # to stop the installation process
        raise ValueError("incorrect pw given 3 times")

class CustomInstaller(install):
    def run(self):
        assert os.getuid() == 0, "You need root priviledge to run the installation"
        if not os.path.exists(BINDIR):
            os.mkdirs(path=BINDIR, mode=0755) # drwxr-xr-x
        call(['apt-get', 'install'] + LIB_DEPENDENCIES)
        call(['gcc', 'chkpw.c', '-o', '{}/chkpw'.format(BINDIR), '-lcrypt'])
        # Assuming there is a unix_chkpwd
        p = Popen('which unix_chkpwd'.split(), stdout=PIPE)
        unix_chkpwd = p.stdout.read().strip()
        p.wait()
        unix_chkpwd_st = os.stat(unix_chkpwd)
        os.chown('{}/chkpw'.format(BINDIR), unix_chkpwd_st.st_uid, unix_chkpwd_st.st_gid)
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
            print("Looks like you have an old installation of typo_auth. Removing it.")
            os.rename(common_auth_orig, common_auth)
        with open(common_auth_orig, 'wb') as f:
            f.write(open(common_auth).read())
        with open(common_auth, 'w') as f:
            f.write('# for allowing typo tolerant login\n'
                    '@include typo_auth\n')
            f.write(open(common_auth_orig).read())
        install.run(self)
        initiate_typodb()


# With the help from http://peterdowns.com/posts/first-time-with-pypi.html
setup(
    name = 'adaptive_typo', # 'loginwitherror',
    packages = ['adaptive_typo'], # this must be the same as the name above
    version = VERSION,
    description = 'Adaptive Typo Tolerance for Debian logins',
    author = 'Rahul Chatterjee, Yuval Pnueli',
    author_email = 'rc737@cornell.edu',
    url = GITHUB_URL,
    download_url = '{}/tarball/{}'.format(GITHUB_URL, VERSION),
    keywords = [
        'Password', 'typo-tolerance', 
        'login-with-errors', 'Login'
    ],
    classifiers = ['Development Status :: 4 - Beta'],
    scripts = ['pam-typoauth'],
    install_requires=[
        'joblib',
        'pycryptodome',
        # 'python-Levenshtein',
        'word2keypress',
        'dataset',
        'zxcvbn',
        'requests'
    ],
    cmdclass={'install': CustomInstaller}
)
