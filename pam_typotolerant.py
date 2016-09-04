import crypt
import pwd
import os, sys
import datetime
from adaptive_typo import typo_db_access
module_path = os.path.dirname(os.path.abspath(__file__))
# CHKPW_EXE = '/sbin/unix_chkpwd'
CHKPW_EXE = '/usr/loca/bin/chkpw' # hardcoded path
NN = 5 # hash cache's size

# sys.path.insert(0, module_path)))
# print sys.path
# from typofixer.checker import BUILT_IN_CHECKERS
# mychecker = BUILT_IN_CHECKERS['ChkBl_keyedit']

def get_user(pamh, flags, argv):
    # getting username
    try:
        user = pamh.get_user(None)
    except pamh.exception, e:
        print "Could not determine user.", e.pam_result
        return e.pam_result
    user = user.lower()
    try:
        pwdir = pwd.getpwnam(user)
    except KeyError, e:
        print "Cound not fid user:", e
        return pamh.PAM_USER_UNKNOWN
    return user, pwdir

def get_password(tmpPrompt, pamh, flags, argv):
    password_prompt = tmpPrompt+";DB pASSWORD:"
    # getting password
    if pamh.authtok:
        print "There is a authtok. Don't know what to do with it.", pamh.authtok
    msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, password_prompt)
    resp = pamh.conversation(msg)
    if not resp.resp_retcode:
        password = resp.resp

    if (not password and \
            (pamh.get_option ('nullok') or (flag & pamh.PAM_DISALLOW_NULL_AUTHTOK))):
        return pamh.PAM_AUTH_ERROR
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
    ret = Top5Corrector(pw)
    ret.add(pw) # Ensure the original `pw` always
    #return ret
    return [pw]

def check_pw(user, pws):
    from subprocess import Popen, PIPE, STDOUT
    p = Popen([CHKPW_EXE, user], stdin=PIPE, stdout=PIPE)
    p.stdin.write('\n'.join(fix_typos(pws)) + '\n')
    #p.stdin.write("{}".format(pws)) # CHANGED
    p.stdin.close()
    ret = p.wait()
    # with open('/etc/typos-pm_sm_auth.txt', 'a') as f:
    #     print "Writing to the file: before chek_pw"
    #     f.write('user: {}, pw: {}, ts: {}\n'.format(user, pws,
    #                                                                             datetime.datetime.now()))
    #     f.write('Return Code: {}'.format(p.returncode))
    # print ''.join(p.stdout.readlines())
    return p.returncode

def pam_sm_authenticate(pamh, flags, argv):
    print "** Typo-tolerant password checking!"
    print "** Typo-DB is ON ** "
    
    ret = get_user(pamh, flags, argv)
    if isinstance(ret, tuple) and len(ret) != 2:
        return ret
    user, pwdir = ret
    typoDB = typo_db_access.UserTypoDB(user)
    ret = get_password(str(typoDB),pamh, flags, argv) #tmp
    if isinstance(ret, tuple) and len(ret) != 2 and ret[0] != 'pw':
        return ret
    _, password = ret

    # changes from now forth
    
    
    if check_pw(user, password) == 0: #i.e - it's the password!
        print "sm_auth: it's the right password" #TODO REMOVE
        # log the entry of the original pwd
        if not typoDB.is_typotoler_init():
            print "sm_auth: initiating typoToler" # TODO REMOVE
            typoDB.init_typotoler(password,NN)
        typoDB.original_password_entered(password) # also updates the log
        # TODO
        
        print "Returning SUCEESS"
        return pamh.PAM_SUCCESS
    else:
        # it's a typo
        t_sk,t_id,is_in = typoDB.fetch_from_cache(password) # also updates the log
        if not is_in: # aka it's not in the cach
            # maybe we should change for a mroe simple check
            # negative t_id in return ?
            print "sm_auth: a new typo!" # TODO REMOVE
            typoDB.add_typo_to_waitlist(password)
            return pamh.PAM_AUTH_ERR
        # it's in cach
        print "sm_auth: in cach" # TODO REMOVE
        typoDB.update_hash_cach_by_waitlist(t_id,t_sk) # also updates the log
        if typoDB.is_typotoler_on():
            print "Returning SUCEESS TypoToler"
            return pamh.PAM_SUCCESS
        # else
        print "sm_auth: but typoToler is OFF" # TODO REMOVE
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
    print check_pw('rahul', 'KiJataSob')
