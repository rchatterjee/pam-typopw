import pytest
import os
import sys
import subprocess


files_to_delete = [
    '/usr/local/etc/typtop.d',
    '/usr/local/bin/typtops.py'
    '/usr/bin/typtop',
    '/usr/bin/typtops.py',
    '/var/log/typtop.log',
    '/var/log/send_typo_log.py',
    '/etc/pam.d/su.orig'
    '/etc/pam.d/login.orig'
    '/etc/pam.d/common-password.org'
]


def test_cleanup():
    for f in files_to_delete:
        assert not os.path.exists(f)
    thisdir = os.path.abspath('.')
    with pytest.raises(ImportError) as imperr:
        sys.path.remove(thisdir)
        import typtop


def install_typtop():
    os.setuid(0)
    os.setgid(0)
    p = subprocess.Popen('sudo -H -u root pip install . '
                         '&& sudo bash ./csrcs/init.sh',
                         shell=True)
    p.wait()


@pytest.fixture(scope="session", autouse=True)
def pytest_sessionstart(request):
    """ before session.main() is called. """
    os.setuid(0)
    os.setgid(0)
    p = subprocess.Popen('sudo -H -u root typtop --uninstall',
                         stdin=subprocess.PIPE, shell=True)
    p.stdin.write('y')
    p.stdin.close()
    p.wait()
    request.addfinalizer(install_typtop)

