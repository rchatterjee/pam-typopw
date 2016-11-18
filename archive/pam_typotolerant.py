
from __future__ import print_function
import pwd
import os, sys
# from pam_typtop.typo_db_access import (
#     UserTypoDB,
#     on_wrong_password,
#     on_correct_password
# )
from subprocess import Popen, PIPE

# module_path = os.path.dirname(os.path.abspath(__file__))
# CHKPW_EXE = '/sbin/unix_chkpwd'
CHKPW_EXE = '/usr/local/bin/chkpw' # hardcoded path
NN = 5 # hash cache's size

DEBUG=0

def eprint(*args, **kwargs):
    if DEBUG==1:
        print(*args, file=sys.stdout, **kwargs)
    elif DEBUG==2:
        print(*args, file=sys.stderr, **kwargs)


def get_user(pamh, flags, argv):
    # getting username
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        eprint("Could not determine user. {}".format(e.pam_result))
        return pamh.PAM_USER_UNKNOWN
    user = user.lower()
    try:
        pwdir = pwd.getpwnam(user)
    except KeyError as e:
        eprint("Cound not fid user:", e)
        return pamh.PAM_USER_UNKNOWN
    return user

def get_password(tmpPrompt, pamh, flags, argv):
    password_prompt = tmpPrompt
    # getting password
    if pamh.authtok:
        eprint("There is a authtok. Don't know what to do with it.", pamh.authtok)
    msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, password_prompt)
    resp = pamh.conversation(msg)
    password = ''
    if not resp.resp_retcode:
        password = resp.resp
    return 'pw', password

def check_pw(user, pw):
    p = Popen([CHKPW_EXE, user], stdin=PIPE, stdout=PIPE)
    p.stdin.write(str(pw) + '\n')
    p.stdin.close()
    try:
        p.wait()
    except OSError as e:
        eprint("ERROR: Could not open {}\n{}".format(CHKPW_EXE, e))
        return -1
    return p.returncode


def pam_sm_authenticate(pamh, flags, argv):
    eprint("** Typo-tolerant password checking!")
    eprint("** Typo-DB is ON ** ")

    ret = get_user(pamh, flags, argv)
    if not isinstance(ret, (basestring, str)):
        return pamh.PAM_USER_UNKNOWN
    user = ret
    # try:
    #     typo_db = UserTypoDB(user)
    # except OSError:
    #     print("Typo DB is probably not initiated.")
    # prompt = typo_db.get_prompt()
    # full_prompt = '{}: '.format(prompt)
    full_prompt = 'aDAPTIVE pASSWORD: '

    ATTEMPT_LIMIT = 3 # Maximum number of attempt allowed
    for _ in range(ATTEMPT_LIMIT):
        ret = get_password(full_prompt, pamh, flags, argv)
        if isinstance(ret, tuple) and len(ret) != 2 and ret[0] != 'pw':
            return pamh.PAM_AUTH_ERR # Should never happen
        _, password = ret
        if not password:
            return pamh.PAM_AUTH_ERR
        if check_pw(user, password) == 0: # i.e - it's the password!
            return pamh.PAM_SUCCESS
    return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    # raise Exception("pam_sm_setcred not initialized")
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    raise Exception("pam_sm_acct_mgmt not initialized")
    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    raise Exception("pam_sm_open_session not initialized")
    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    raise Exception("pam_sm_close_session not initialized")
    return pamh.PAM_SUCCESS    

def pam_sm_chauthtok(pamh, flags, argv):
    raise Exception("pam_sm_chauthtok not initialized")
    return pamh.PAM_SUCCESS


if __name__ == "__main__":
    eprint(check_pw('rahul', 'KiJataSob'))
