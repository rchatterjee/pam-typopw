from __future__ import print_function
import crypt
import pwd
import os, sys
import datetime
from adaptive_typo import typo_db_access

# module_path = os.path.dirname(os.path.abspath(__file__))
# CHKPW_EXE = '/sbin/unix_chkpwd'
CHKPW_EXE = '/usr/local/bin/chkpw' # hardcoded path
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
    except pamh.exception, e:
        eprint("Could not determine user. {}".format(e.pam_result))
        return e.pam_result
    user = user.lower()
    try:
        pwdir = pwd.getpwnam(user)
    except KeyError, e:
        eprint("Cound not fid user:", e)
        return pamh.PAM_USER_UNKNOWN
    return user, pwdir

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
        if len(pw)<7: return [pw] 
        return set([
            pw.capitalize(),
            pw.swapcase(),
            pw[:-1],
            pw[1:],
            pw.lower(),
            pw.upper()
        ])
    # if allow old top5 corrections
    ret = Top5Corrector(pw) # right now IGORING.
    ret.add(pw) # Ensure the original `pw` always
    #return ret
    return [pw]

def check_pw(user, pws):
    from subprocess import Popen, PIPE, STDOUT, call
    p = Popen([CHKPW_EXE, user], stdin=PIPE, stdout=PIPE)
    p.stdin.write('\n'.join(fix_typos(pws)) + '\n')
    p.stdin.close()
    try:
        ret = p.wait()
    except OSError:
        return -1
    # with open('/etc/typos-pm_sm_auth.txt', 'a') as f:
    #     eprint("Writing to the file: before chek_pw")
    #     f.write('user: {}, pw: {}, ts: {}\n'.format(user, pws,
    #     datetime.datetime.now()))
    #     f.write('Return Code: {}'.format(p.returncode))
    # eprint(''.join(p.stdout.readlines()))
    return p.returncode

def on_correct_password(typo_db, password):
    eprint("sm_auth: it's the right password") #TODO REMOVE
    # log the entry of the original pwd
    if not typo_db.is_typotoler_init():
        eprint("sm_auth: initiating typoToler") # TODO REMOVE
        typo_db.init_typotoler(password, NN)
    typo_db.original_password_entered(password) # also updates the log
    return True


def on_wrong_password(typo_db, password):
    t_sk, t_id, is_in = typo_db.fetch_from_cache(password) # also updates the log
    if not is_in: # aka it's not in the cache, 
        eprint("sm_auth: a new typo!") # TODO REMOVE
        typo_db.add_typo_to_waitlist(password)
        return False
    else: # it's in cach
        eprint("sm_auth: in cach") # TODO REMOVE
        typo_db.update_hash_cach_by_waitlist(t_id,t_sk) # also updates the log
        if typo_db.is_typotoler_on():
            eprint("Returning SUCEESS TypoToler")
            return True
        else:
            eprint("sm_auth: but typoToler is OFF") # TODO REMOVE
            return False


def pam_sm_authenticate(pamh, flags, argv):
    eprint("** Typo-tolerant password checking!")
    eprint("** Typo-DB is ON ** ")
    
    ret = get_user(pamh, flags, argv)
    if isinstance(ret, tuple) and len(ret) != 2:
        return ret
    user, pwdir = ret
    typo_db = typo_db_access.UserTypoDB(user)

    ATTEMPT_LIMIT = 3 # Maximum number of attempt allowed
    for _ in range(ATTEMPT_LIMIT):
        ret = get_password('aDAPTIVE pASSWORD: ', pamh, flags, argv)
        if isinstance(ret, tuple) and len(ret) != 2 and ret[0] != 'pw':
            return pamh.PAM_AUTH_ERR # Should never happen
        _, password = ret
        iscorrect = False
        if check_pw(user, password) == 0: # i.e - it's the password!
            iscorrect = on_correct_password(typo_db, password)
        else:
            iscorrect = on_wrong_password(typo_db, password)

        if iscorrect:
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
