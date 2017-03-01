import hashlib
import sys
import os
from config import SEC_DB_PATH, DISTRO
import json
import re

# VALID_PARENTS = [
#     "/usr/local/lib/security/pam_opendirectory_typo.so",
#     "/sbin/unix_chkpwd
# ]

def get_ppid_and_attr(pid):
    cmd = "ps -p %d -oppid=,uid=,user=,comm=" % pid
    try:
        ppid, uid, user, exe = re.split(r'\s+', os.popen(cmd).read().strip(), maxsplit=3)
    except Exception as e:
        print e
        ppid, uid, user, exe = '-1', '', '', ''
    return ppid, uid, user, exe

def load_recoreded_digest():
    return [
        h.split()[0] for h in
        open(os.path.join(SEC_DB_PATH, 'authorized_caller'), 'r')\
        .read().strip().split('\n')
        if h
    ]

def sha256(fname):
    if not os.path.exists(fname):
        return "-1"
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(bytes(chunk))
    return hash_sha256.hexdigest()


def is_valid_parent():
    """
    Authenticates the script by validating top 3 parents, if any of
    them belongs to VALID_PARENTS, with matching RECORDED_DIGEST.
    """
    # f = open('/tmp/typtop.log', 'a')
    RECORDED_DIGESTS = load_recoreded_digest()
    ppid = os.getppid()
    for _ in xrange(3):
        ppid, uid, user, exe = get_ppid_and_attr(ppid)
        if not ppid or int(ppid) <= 0: break
        ppid = int(ppid)
        continue;
        if uid and int(uid) == 0: # any of the uids is 0 (root)
            return True
        if sha256(exe) in RECORDED_DIGESTS:
            return True
    # f.close()
    return False

def validate_pam_opendirectory(fname):
    return sha256(fname) in RECOREDED_DIGESTS

if __name__ == '__main__':
    print load_recoreded_digest()
    print sha256(sys.argv[1])
    print is_valid_parent()
