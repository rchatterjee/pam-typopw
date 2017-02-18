from __future__ import print_function

# import os
# from subprocess import Popen, call, PIPE
# from glob import glob
# try:
from setuptools import setup

# from setuptools.command.install import install
# except ImportError as e:
#     print(e)
#     print("Setuptools not found, if installation fails, "
#           "please install setuptools, and try again.")
#     from distutils.core import setup
#     from distutils.command.install import install

from typtop.config import VERSION, set_distro

GITHUB_URL = 'https://github.com/rchatterjee/pam-typopw' # URL in github repo
SCRIPTS = {
    'typtop/send_typo_log.py',
    'typtop/typtops.py'
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
    # 'dataset',
    'zxcvbn',
    'requests==2.11.1', # 2.12 has issue with x509 cetificate
    'psutil',
    'pyyaml'
]

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
    # scripts=SCRIPTS,
    entry_points = {
        'console_scripts': [
            'typtops.py = typtop.typtops:main',
            'send_typo_log.py = typtop.send_typo_log:main']
    },
    license='MIT',
    package_dir={'typtop': 'typtop/'},
    package_data={
        'typtop': ['../LICENSE', '../README.md', 'typtopserver.crt'],
    },
    data_files=[], # DATA_FILES,
    include_package_data=True,
    options={'py2app': OPTIONS},
    classifiers=['Development Status :: 4 - Beta'],
    install_requires=PYTHON_DEPS,
    # cmdclass={'install': CustomInstaller},
    zip_safe=True,
)
