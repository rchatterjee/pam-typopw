#
# Duplicates pam_permit.c
#
from edits import Edits
import crypt
import pwd

E = Edits()
ALLOWED_EDITS = E.ALLOWED_EDITS[:4]

def get_user(pamh, flags, argv):
  # getting username
  try:
    user = pamh.get_user(None)
  except pamh.exception, e:
    print "Could not determine user.", e.pam_result
    return e.pam_result
  # TODO - check if the user is preset/known
  try:
    pwdir = pwd.getpwnam(user)
  except KeyError, e:
    print e
    return pawm.PAM_USER_UNKNOWN
  print "User is:", user
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
  ret = E.fast_modify(pw, apply_edits=ALLOWED_EDITS)
  ret.add(pw)
  return ret

def check_pw(user, pw):
  from subprocess import Popen, PIPE, STDOUT
  p = Popen(['chkpw', user], stdin=PIPE)
  for tpw in fix_typos(pw):
    p.communicate(input=tpw)
  print "Return code:", p.returncode
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
  # def check(pw):
  #   print "*** Trying password: (REMOVE THIS LINE)", pw, pwdir.pw_passwd
  #   # crypt_pw = crypt.crypt(pw, pwdir.pw_passwd)
  #   # return crypt_pw and (crypt_pw == pwdir.pw_passwd)

  # if any(check(pw) for pw in fix_typos(password)):
  if check_pw(user, pw):
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
