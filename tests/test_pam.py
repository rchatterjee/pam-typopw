import pytest
import pam
import os

user = 'tmp2540'
pws = [
    "superpass",
    "Superpass",  # allow
    "superpass1",  # allow
    "SuperPass",
    "suprepass"
]


def get_correct_pw():
    return pws[0]


def check(pindex):
    assert pindex < len(pws)
    return pam.authenticate(user, pws[pindex], service='su')


def test_login_correctpw():
    assert check(0)
    assert check(1)
    assert check(2)
    assert not check(3)


def test_train_pass():
    for i in range(2):
        check(3)
        check(4)
        check(0)
    assert not check(3)
    assert check(4)
    assert check(0)


def pytest_sessionstart(session):
    """ before session.main() is called. """
    import crypt
    pw = crypt.crypt(pws[0])
    os.system("sudo useradd -u 2540 -p {!r} {}".format(pw, user))


def pytest_sessionfinish(session, exitstatus):
    """ whole test run finishes. """
    os.system("sudo userdel {}".format(user))
