import hashlib
import sys
import os
import psutil
from config import SEC_DB_PATH, DISTRO
import json

# VALID_PARENTS = [
#     "/usr/local/lib/security/pam_opendirectory_typo.so",
#     "/sbin/unix_chkpwd
# ]

def load_recoreded_digest():
    return [
        h.split()[0] for h in
        open(os.path.join(SEC_DB_PATH, 'authorized_caller'), 'r')\
        .read().strip().split('\n')
        if h
    ]

def sha256(fname):
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
    def attrib(p):
        if p:
            return p.as_dict(attrs=['exe', 'uids', 'username'])
    p = psutil.Process(os.getppid()).parent()
    for _ in xrange(3):
        d = attrib(p)
        if not d: break
        if not d['exe']: break
        # f.write(json.dumps(d) + '\n')
        if not d['uids'][0]: # any of the uids is 0 (root)
            return True
        if sha256(d['exe']) in RECORDED_DIGESTS:
            return True
        p = p.parent()
    # f.close()
    return False

def validate_pam_opendirectory(fname):
    return sha256(fname) in RECOREDED_DIGESTS

if __name__ == '__main__':
    print load_recoreded_digest()
    print sha256(sys.argv[1])
