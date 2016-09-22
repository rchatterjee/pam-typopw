from adaptive_typo.typo_db_access import UserTypoDB
from subprocess import Popen, STDOUT # 
import getpass
import pwd

CHKPW_EXE = '/usr/local/bin/chkpw' # hardcoded path # TODO

def main():
    # make sure that root
    # but if it's called from the install there's no need for that
    # optional - to compile this script
    
    user = raw_input("enter username\n")
    # some checks agaist bad input? TODO
    try:
        # checks that such a user exists:
        homedir = pwd.getpwnam(user).pw_dir
    except Exception as e:
        print "Error:{}".format(e.message)
    else:
        pw = getpass.getpass()
        # check that it's the right pw
        right_pw = check_pw(user,pw) == 0
        if not right_pw:
            print "Incorrect pw"
        else:
            print "correct pw!" # TODO REMOVE
            # do things
            tb = UserTypoDB(user)
            tb.init_typo_toler(pw)
            
        return 0

# from pam_typotolerance
def check_pw(user, pw):
    from subprocess import Popen, PIPE, STDOUT, call
    p = Popen([CHKPW_EXE, user], stdin=PIPE, stdout=PIPE)
    p.stdin.write('\n'.join([pw]) + '\n')
    p.stdin.close()
    try:
        ret = p.wait()
    except OSError:
        return -1
    return p.returncode

if __name__ == "__main__":
    main()
