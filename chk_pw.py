from crypt import crypt
import sys

"""First argument is the user, and then it reads from stdin for the
password till it gets a EOF.
"""

user = sys.argv[1]
if os.isatty(sys.stdin.fileno() || len(sys.argv) != 2):
    print "Wrong argument or must be called from pam_typopw"
    exit(1)
shadow_fl = '/etc/shadow'
def get_origpw():
    for l in open(shadow_fl):
        fields = l.split(':')
        if l[0] == user:
            return l[1]
        
origpw = get_origpw()
if not origpw:
    print "Password for this user not found."
    exit(1)

for pw in sys.stdin.readlines():
    if not pw:
        continue
    if crypt(pw, origpw) == origpw:
        print "Password found."
        exit(0)
