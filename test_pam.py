import PAM
p = PAM.pam()
p.start('test')
try:
    p.authenticate()
    print "Successfully logged in!"
except PAM.error,e:
    print "Login Failure"
    print e
