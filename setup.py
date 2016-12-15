
from __future__ import print_function
import os
from subprocess import Popen, call, PIPE
from glob import glob
# try:
from setuptools import setup
from setuptools.command.install import install
# except ImportError as e:
#     print(e)
#     print("Setuptools not found, if installation fails, "
#           "please install setuptools, and try again.")
#     from distutils.core import setup
#     from distutils.command.install import install

import typtop
from typtop.config import VERSION, BINDIR, SEC_DB_PATH, set_distro

GITHUB_URL = 'https://github.com/rchatterjee/pam-typopw' # URL in github repo
SCRIPTS = {
    'typtop/send_typo_log.py',
    'typtops.py'
}

DISTRO = set_distro()

LIB_DEPENDENCIES = {
    'debian': [
        'libffi-dev', 'python-pkg-resources', 'libssl-dev',
        'python-setuptools', 'python-dev',
    ],
    # Fedora does not have python-pam!! So, we cannot write the fedora
    # version.
    'fedora': [
        'libffi-devel', 'openssl-devel',
        'python-devel', 'python-pip', 'python-setuptools',
    ],
    'darwin': [],
}[DISTRO]

PACMAN = {
    'debian': 'apt-get install -y'.split(),
    'fedora': 'yum install -y'.split(),
    'darwin': [],
}[DISTRO]

PYTHON_DEPS = [
    'cryptography',
    # 'pycryptodome',
    'word2keypress',
    'dataset',
    'zxcvbn',
    'requests',
    'psutil'
]


class CustomInstaller(install):
    """
    It's a custom installer class, subclass of install.
    """
    def linux_run(self):
        call(PACMAN + LIB_DEPENDENCIES)

        # Assuming there is a unix_chkpwd
        chkpw_proc = Popen('which unix_chkpwd'.split(), stdout=PIPE)
        unix_chkpwd = chkpw_proc.stdout.read().strip()
        chkpw_proc.wait()
        unix_chkpwd_st = os.stat(unix_chkpwd)
        # Compile the new unix_chkpwd, and the make will also copy them
        # Backup old binary, and replace with the new one.
        assert os.getuid() == 0, \
            "You need root priviledge to run the installation"
        if not os.path.exists(BINDIR):
            os.makedirs(path=BINDIR, mode=0755) # drwxr-xr-x
        os.system('cd ./linux/unixchkpwd/ && make && make install && cd -')

        # In Linux, now the pam is unchanged, so no need to install
        # any pam-conf. Just replace the unix_chkpwd and we shouold be
        # good to go.
        # common_auth = {
        #     'debian': '/etc/pam.d/common-auth',
        #     'fedora': '/etc/pam.d/system-auth'
        # }[DISTRO]
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

        # shadow_stat = os.stat('/etc/shadow')
        # # -rw-r----- 1 root shadow 1.2K Nov  1 20:27 /etc/shadow
        # if not os.path.exists(SEC_DB_PATH):
        #     os.makedirs(SEC_DB_PATH, mode=0650)
        # os.chown(SEC_DB_PATH, shadow_stat.st_uid, shadow_stat.st_gid)
        # Popen('cp -vf {} {}/'.format(' '.join(SCRIPTS), BINDIR).split()).wait()

    def darwin_run(self):
        # 1. compile the new pam_opendirectory.so, and change the common-auth in pam-conf
        os.system('cd ./osx/pam_opendirectory/ && make && make install && cd -')

    def run(self):
        print("Running instal for {}".format(DISTRO))
        # try to see if cryptography can be installed. It's more efficient
        #  Popen('easy_install pip'.split()).wait()
        # p = Popen('pip install cryptography'.split())
        # if p.wait() != 0:
        #    Popen("pip install pycryptodome".split())

        if DISTRO == 'darwin':
            self.darwin_run()
        else:
            self.linux_run()

        try:
            self.do_egg_install()
        except AttributeError:
            # this ignores all install_requires
            print("\n>> The installation had some glitches. "
                  "Can you please re-run the install command?")
        # initiate_typodb() # Because pip install is non-interactive

OPTIONS = {
    'argv_emulation': True,
    # 'packages': ['requests', 'requests', 'selenium']
}

# Shitty python way of getting these files
# DATA_FILES = [
#     ('/tmp/typtop_osx/pam_opendirectory', [
#         "osx/pam_opendirectory/pam_opendirectory_typo.c",
#         "osx/pam_opendirectory/typtops.c",
#         "osx/pam_opendirectory/run_as_root.c",
#         "osx/pam_opendirectory/Makefile"
#     ]),
#     ('/tmp/typtop_linux/unixchkpwd', [])
# ]
# With the help from http://peterdowns.com/posts/first-time-with-pypi.html
setup(
    name='typtop', # 'loginwitherror',
    # app=['typtop/dbaccess.py'],
    packages=['typtop'], # this must be the same as the name above
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
    scripts=SCRIPTS,
    license='MIT',
    package_dir={'typtop': 'typtop/'},
    package_data={
        'typtop': ['LICENSE', 'README.md'],
    },
    data_files=[], # DATA_FILES,
    include_package_data=True,
    options={'py2app': OPTIONS},
    classifiers=['Development Status :: 4 - Beta'],
    install_requires=PYTHON_DEPS,
    # cmdclass={'install': CustomInstaller},
    zip_safe=True,
)
