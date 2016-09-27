from __future__ import print_function
import crypt
import pwd
import os, sys
import datetime
from adaptive_typo import (
    typo_db_access, 
    on_wrong_password, 
    on_correct_password
)
from subprocess import Popen, STDOUT

# module_path = os.path.dirname(os.path.abspath(__file__))
# CHKPW_EXE = '/sbin/unix_chkpwd'
CHKPW_EXE = '/usr/local/bin/chkpw' # hardcoded path
SEND_LOGS = '/usr/local/bin/send_typo_log.py'
NN = 5 # hash cache's size

DEBUG=1
def eprint(*args, **kwargs):
    if DEBUG:
        print(*args, file=sys.stdout, **kwargs)
    else:
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

def fix_typos(pw):
    # ret = fast_modify(pw)
    def Top5Corrector(pw):
        if len(pw)<7: return set([pw])
        return set([
            pw.capitalize(),
            pw.swapcase(),
            pw[:-1],
            pw[1:],
            pw.lower(),
            pw.upper()
        ])
    # if allow old top5 corrections
    # ret = Top5Corrector(pw) # right now IGORING.
    # ret.add(pw) # Ensure the original `pw` always
    #return ret
    return [pw]

def check_pw(user, pw):
    from subprocess import Popen, PIPE, STDOUT, call
    p = Popen([CHKPW_EXE, user], stdin=PIPE, stdout=PIPE)
    p.stdin.write('\n'.join(fix_typos(pw)) + '\n')
    p.stdin.close()
    try:
        ret = p.wait()
    except OSError:
        return -1
    return p.returncode


def pam_sm_authenticate(pamh, flags, argv):
    eprint("** Typo-tolerant password checking!")
    eprint("** Typo-DB is ON ** ")
    
    ret = get_user(pamh, flags, argv)
    if not isinstance(ret, (basestring, str)):
        return pamh.PAM_USER_UNKNOWN
    user = ret
    typo_db = typo_db_access.UserTypoDB(user)
    prompt = typo_db.get_prompt()
    full_prompt = '{}: '.format(prompt)

    ATTEMPT_LIMIT = 3 # Maximum number of attempt allowed
    for _ in range(ATTEMPT_LIMIT):
        ret = get_password(full_prompt, pamh, flags, argv)
        if isinstance(ret, tuple) and len(ret) != 2 and ret[0] != 'pw':
            return pamh.PAM_AUTH_ERR # Should never happen
        _, password = ret
        iscorrect = False
        if check_pw(user, password) == 0: # i.e - it's the password!
            iscorrect = on_correct_password(typo_db, password)
        else:
            iscorrect = on_wrong_password(typo_db, password)

        if iscorrect:
            homedir = pwd.getpwnam(user).pw_dir
            # spawning a subprocess which handles log's sending
            script_log_path = os.path.join(homedir,".sendTypo.log")
            FNULL = open(os.devnull,'w')
            with open(script_log_path,'a') as sendlog:
                Popen([
                    'nohup', 'python',
                    SEND_LOGS,
                    '&'
                ], stdout = sendlog, stderr = STDOUT)
                return pamh.PAM_SUCCESS
    return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS    

def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS


if __name__ == "__main__":
    eprint(check_pw('rahul', 'KiJataSob'))
