import hashlib
import sys
import os
import psutil

RECOREDED_DIGESTS = [
    "__recoreded_digest__1",
    "__recoreded_digest__2"
]
    

VALID_PARENTS = [
    "/usr/local/lib/security/pam_opendirectory_typo.so"
]

def md5(fname):
    hash_md5 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def is_valid_parent():
    """Authenticates the script by validating top 3 parents, if any of
them belongs to VALID_PARENTS, with matching RECORDED_DIGEST.

    """
    p = psutil.Process(os.getppid())
    for _ in xrange(3):
        fname = p.exe()
        if fname in VALID_PARENTS and md5(fname) in RECORDED_DIGESTS:
            return True
        p = p.parent()
    return False

def validate_pam_opendirectory(fname):
    return md5(fname) in RECOREDED_DIGESTS

if __name__ == '__main__':
    print md5(sys.argv[1])
