#!/usr/bin/env python

try:  # If you installed the python-pam using apt-get
    import PAM
except ImportError: # if it is installed using pip
    import sys
    sys.path.append('/usr/lib/python2.7/dist-packages/')
    import PAM

p = PAM.pam()
p.start('typo_auth')
try:
    p.authenticate()
    print "Successfully logged in!"
except PAM.error as e:
    print "Login Failure"
    print e

