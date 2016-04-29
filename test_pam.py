import PAM
p = PAM.pam()
p.start('test')

try:
    print p.authenticate()
except PAM.error,e:
    print "Login Failure"
    print e
