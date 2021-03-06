import pytest
import pam   # python-pam
import os
from typtop.config import SEC_DB_PATH, DISTRO
import subprocess
import time

user = 'tmp2540'
pws = [
    "superpass",  # 0, true pass
    "Superpass",  # 1, allow
    "superpass1", # 2, allow
    "SuperPass",  # 3, not allow
    "suprepass"   # 4, allow
]

pam_exec = pam.pam()

@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    monkeypatch.setattr("typtop.config.TEST", True)


def get_correct_pw():
    return pws[0]

# TODO: run su in a seperate shell, and test.
# def run_su(user):
#     subprocess.Popen('su {}'.format(user))

def check(pindex):
    assert pindex < len(pws)
    return pam_exec.authenticate(user, pws[pindex], service='su')

@pytest.mark.skipif(
    DISTRO=='windows',
    reason="pam does not work here! Need find new method "
)
def test_login_correctpw():
    assert check(0)
    time.sleep(.4)
    assert check(1)
    assert check(2)
    assert not check(3)


@pytest.mark.skipif(
    DISTRO=='windows',
    reason="pam does not work here! Need find new method "
)
def test_train_pass():
    assert not check(4)
    for _ in range(2):
        check(3)
        if check(4):
            break
        check(0)
    assert not check(3)
    assert check(4)
    assert check(0)


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        return
    import pwd, grp
    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)


def grab_privileges():
    try:
        os.setuid(0)
        os.setgid(0)
    except Exception:
        pass


@pytest.fixture(scope="session", autouse=True)
def pytest_sessionstart(request):
    """ before session.main() is called. """
    import crypt, shutil
    pw = crypt.crypt(pws[0], 'ab')
    dbpath = os.path.join(SEC_DB_PATH, user)
    thisdir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(dbpath):
        subprocess.Popen("sudo rm -rf {}".format(dbpath), shell=True)
    if DISTRO == 'darwin':
        subprocess.Popen(
            "sudo {2}/create_mac_user.sh {0} {1}"
            .format(user, pws[0], thisdir),
            shell=True
        )
    elif DISTRO == 'windows':
        print("WINDOWS: Ignoring!!")
    else:
        cmd = "sudo {2}/create_linux_user.sh {0} {1}".format(user, pw, thisdir),
        subprocess.Popen(
            cmd,
            shell=True
        )
        print("LINUX: {}".format(cmd))
    assert check(0)
