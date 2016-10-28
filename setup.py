
from __future__ import print_function
import os
from subprocess import Popen, call, PIPE
try:
    from setuptools import setup
    from setuptools.command.install import install
except ImportError as e:
    print(e)
    print("Setuptools not found, if installation fails, "
          "please install setuptools, and try again.")
    from distutils.core import setup
    from distutils.command.install import install

from pam_typtop import VERSION

GITHUB_URL = 'https://github.com/rchatterjee/pam-typopw' # URL in github repo
BINDIR = '/usr/local/bin'
SEC_DB_PATH = '/etc/pam_typtop'
SCRIPTS = [
    'pam_typotolerant.py', 'send_typo_log.py',
    'typtop'
]


def set_distro():
    import platform
    dist = platform.linux_distribution()[0].lower()
    if dist in ('ubuntu', 'debian', 'lubuntu', 'kubuntu'):
        return 'debian'
    elif dist in ('fedora', 'red-hat', 'centos'):
        return 'fedora'
    else:
        raise ValueError("Not supported for your OS: {}".format(dist))

DISTRO = set_distro()


LIB_DEPENDENCIES = {
    'debian': [ 'libpam-python', 'python-pam',
                 'libffi-dev', 'python-pkg-resources', 'libssl-dev',
                 'python-setuptools', 'python-dev', ],
    'fedora': [ 'libffi-devel', 'openssl-devel',
                 'python-devel', 'python-pip', 'python-setuptools',
                 'libpam-python', 'python-pam', 'libpam-python' ]
}[DISTRO]

PACMAN = {
    'debian': 'apt-get install -y'.split(),
    'fedora': 'yum install -y'.split()
}[DISTRO]

PYTHON_DEPS = [ 
    'cryptography', 
    'word2keypress', 
    'dataset', 
    'zxcvbn', 
    'requests'
]

class CustomInstaller(install):
    """
    It's a custom installer class, subclass of install.
    """
    def run(self):
        assert os.getuid() == 0, \
            "You need root priviledge to run the installation"
        if not os.path.exists(BINDIR):
            os.makedirs(path=BINDIR, mode=0755) # drwxr-xr-x
        call(PACMAN + LIB_DEPENDENCIES)
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
        common_auth = {
            'debian': '/etc/pam.d/common-auth',
            'fedora': '/etc/pam.d/system-auth'
        }[DISTRO]
        common_auth_orig = '/etc/pam.d/common-auth.orig'
        with open('/etc/pam.d/typo_auth', 'wb') as f:
            f.write(
                "auth  sufficient  pam_python.so  {}/pam_typotolerant.py\n"\
                .format(BINDIR)
            )
        if os.path.exists(common_auth_orig):
            print("Looks like you have an old installation of typo_auth. "\
                  "Removing it.")
            os.rename(common_auth_orig, common_auth)
        with open(common_auth_orig, 'wb') as f:
            f.write(open(common_auth).read())
        with open(common_auth, 'w') as f:
            f.write('# for allowing typo tolerant login\n'
                    '@include typo_auth\n')
            f.write(open(common_auth_orig).read())

        try:
            self.do_egg_install()
        except AttributeError:
            # this ignores all install_requires
            print("\n>> The installation had some glitches. "
                  "Can you please re-run the install command?")
        # initiate_typodb() # Because pip install is non-interactive


# With the help from http://peterdowns.com/posts/first-time-with-pypi.html
setup(
    name='pam_typtop', # 'loginwitherror',
    packages=['pam_typtop'], # this must be the same as the name above
    version=VERSION,
    description='Adaptive typo-tolerant password checking for Debian logins',
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
    install_requires=PYTHON_DEPS,
    cmdclass={'install': CustomInstaller},
    zip_safe=False
)
