#
# Duplicates pam_permit.c
#
import crypt
import pwd
import os, sys
import datetime

module_path = os.path.dirname(os.path.abspath(__file__))
# sys.path.insert(0, module_path)))
# print sys.path
# from typofixer.checker import BUILT_IN_CHECKERS
# mychecker = BUILT_IN_CHECKERS['ChkBl_keyedit']
CHKPW_EXE = os.path.join(module_path, 'chkpw')

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
    return pawm.PAM_USER_UNKNOWN
  return user, pwdir

def get_password(pamh, flags, argv):
  password_prompt = "pASSWORD:"
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
  return ret

def check_pw(user, pws):
  from subprocess import Popen, PIPE, STDOUT
  p = Popen([CHKPW_EXE, user], stdin=PIPE, stdout=PIPE)
  for tpw in fix_typos(pws):
    print >>sys.stderr, ">>", tpw
    p.stdin.write(tpw+'\n')
  p.stdin.close()
  ret = p.wait()
  # with open('/etc/typos-pm_sm_auth.txt', 'a') as f:
  #   print "Writing to the file: before chek_pw"
  #   f.write('user: {}, pw: {}, ts: {}\n'.format(user, pws,
  #                                       datetime.datetime.now()))
  #   f.write('Return Code: {}'.format(p.returncode))
  return p.returncode

def pam_sm_authenticate(pamh, flags, argv):
  print "** Typo-tolerant password checking!"
  ret = get_user(pamh, flags, argv)
  if isinstance(ret, tuple) and len(ret) != 2:
    return ret
  user, pwdir = ret
  ret = get_password(pamh, flags, argv)
  if isinstance(ret, tuple) and len(ret) != 2 and ret[0] != 'pw':
    return ret
  _, password = ret

  if check_pw(user, password) == 0:
    print "Returning SUCEESS"
    return pamh.PAM_SUCCESS
  else:
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
