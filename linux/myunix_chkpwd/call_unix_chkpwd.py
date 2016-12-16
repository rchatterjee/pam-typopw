#!/usr/bin/python

import os, sys
import subprocess

cmd = './chkpw {} nullok'.format(sys.argv[1]).split()
# cmd = '/sbin/unix_chkpwd {} nullok'.format(sys.argv[1]).split()
p = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE, stdin=subprocess.PIPE
)

# print p
# print dir(p)

# p.stdin.write(raw_input('Password: '))
p.stdin.write('kidarun')
p.stdin.close()
print p.wait()
print p.stdout.read()
