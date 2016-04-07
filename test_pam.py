import PAM
p = PAM.pam()
p.start('test')

print p.authenticate()
