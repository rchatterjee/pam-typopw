from __future__ import print_function

# import ez_setup
# ez_setup.use_setuptools()
import sys
from typtop.config import (
    VERSION, set_distro, first_msg, GITHUB_URL
)

if sys.argv[-1] == 'tag':
    import subprocess
    subprocess.Popen("git tag -f -a {0} -m 'Release: {0}'"\
                     .format(VERSION), shell=True)
    exit(0)

if sys.argv[-1] == 'upload':
    import subprocess
    subprocess.Popen(
        "git push origin --tags && git push origin master", shell=True
    )
    subprocess.Popen(
        "python setup.py bdist_wheel bdist sdist upload -r pypitest", shell=True
    )
    exit(0)

if sys.argv[-1] == 'publish':
    import subprocess
    subprocess.Popen(
        "git push origin --tags && git push origin master", shell=True
    )
    subprocess.Popen(
        "python setup.py bdist_wheel bdist sdist upload -r pypi", shell=True
    )
    exit(0)

from setuptools import setup


SCRIPTS = [
    # 'typtop/send_typo_log.py',    # all in typtop
    'typtop/typtops.py'
]

DISTRO = set_distro()

# OLD, not used now
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
    'arch'  : [],
}[DISTRO]

PACMAN = {
    'debian': 'apt-get install -y'.split(),
    'fedora': 'yum install -y'.split(),
    'darwin': [],
    'arch': [],
}[DISTRO]

PYTHON_DEPS = [
    'cryptography',
    # 'pycryptodome',
    'word2keypress',
    # 'dataset',
    'zxcvbn',
    'requests==2.11.1', # 2.12 has issue with x509 cetificate
    'pyyaml',
    'distro',
]

OPTIONS = {
    'argv_emulation': True,
    # 'packages': ['requests', 'requests', 'selenium']
}

    
TEST_REQUIRES = ['pam', 'pytest']

setup(
    name='typtop',   # 'loginwitherror',
    # app=['typtop/dbaccess.py'],
    packages=['typtop'], # this must be the same as the name above
    version=VERSION,
    description='Adaptive typo-tolerant password checking for Debian logins',
    long_description=first_msg,
    author='Rahul Chatterjee, Yuval Pnueli',
    author_email='rc737@cornell.edu',
    url=GITHUB_URL,
    download_url='{}/tarball/{}'.format(GITHUB_URL, VERSION),
    keywords=[
        'Password', 'typo-tolerance',
        'login-with-errors', 'Login'
    ],
    # scripts=SCRIPTS,
    entry_points={
        'console_scripts': [
            'typtops.py = typtop.typtops:main',
            'send_typo_log.py = typtop.send_typo_log:main']
    },
    license='MIT',
    # package_dir={'typtop': 'typtop/'},
    # package_data={
    #     'typtop': ['../LICENSE', '../README.md', 'typtopserver.crt'],
    # },
    data_files=[],  # DATA_FILES,
    include_package_data=True,
    options={'py2app': OPTIONS},
    classifiers=['Development Status :: 4 - Beta'],
    install_requires=PYTHON_DEPS,
    # cmdclass={'install': CustomInstaller},
    zip_safe=True,
)


