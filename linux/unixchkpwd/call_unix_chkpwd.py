#!/usr/bin/python

import os, sys
import subprocess

cmd = './unix_chkpwd {} nullok'.format(sys.argv[1]).split()
p = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE, stdin=subprocess.PIPE
)

# print p
# print dir(p)

# p.stdin.write(raw_input('Password: '))
p.stdin.write('arparchinaa')
p.stdin.close()
print p.wait()
# print p.stdout.read()
