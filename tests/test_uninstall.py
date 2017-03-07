import pytest
import os


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
    with pytest.raises(ImportError) as imperr:
        import typtop


def pytest_sessionstart(session):
    """ before session.main() is called. """
    os.system('typtop --uninstall')


