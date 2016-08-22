"""
** NOTE **
I am rewriting the cache management using sqlite3 in the
file new_pwcache.py. Unless this note is removed don't use this file.


This file will contian the class PwCache, which basically takes care
of in memory and in file cache management.

"""
import time
import json
import gc
import tempfile
import string
import os, sys
import crypt

CACHE_SIZE = 11
INMEM_CACHE_LIFE = 30 # INMEM cache is puged after 30 sec
PWFILE = "cachepw_file.json" # This file is a dictionary from username
                             # to the list of apasswords
LOG_FL = open('typoauth.log', 'a+')
DEBUG = True 

def salt(n=83):
    """returns n charater long salt, from [a-zA-Z0-9]
    """
    s = string.ascii_letters + string.digits
    return ''.join(s[ord(t) % len(s)] for t in os.urandom(n))

def hash_pw(pw, crpw=''):
    if not crpw:
        crpw = '$6${}$'.format(salt(83))
    return crypt.crypt(pw, crpw)


class PwCache(object):
    def __init__(self):
        """Reads the user's data from the PWFILE and return the dict
        corresponding to the user specified by @username.
        """
        try:
            with open(PWFILE) as pwf:
                self._PW_DB = json.load(pwf)
        except IOError, e:
            log(e)
            self._PW_DB = {}
        self._inmem_cache = {user: [] for user in self._PW_DB}
    
    def initialize(self, username, password, shadow_pw):
        """CAUTION: It will delete any old entries and rewrite with
        new password, and its hashes with different salts 
        """
        # TODO - do we need passwod?
        self._PW_DB[username] = [(hash_pw(password), 0)
                                       for _ in xrange(CACHE_SIZE)]
        self._PW_DB[username][0] = (shadow_pw, 1)
        self.flush(username, password, shadow_pw)

    def delete_old_cache_entries(self):
        """
        Delete password entries that are very old.
        """
        curr_time = time.time()
        for username in self._inmem_cache: # remove the old passwords
            udb = self._inmem_cache[username]
            while i<len(udb) and udb[i][1]<curr_time - 2*INMEM_CACHE_LIFE:
                i+=1
            self._inmem_cache[username] = udb[i:]
        gc.collect()

    def put(self, username, password):
        """This is a mistyped password submission. Save it in memory for 30
        sec.
        """
        curr_time = time.time()
        self.delete_old_cache_entries()
        if username not in self._inmem_cache:
            self._inmem_cache[username] = []
        self._inmem_cache[username].append((password, curr_time))

    def get(self, username):
        """
        returns a sorted list of passwords for username
        """
        pws = sorted(self._PW_DB.get(username, []), 
                     key=lambda x: x[1], reverse=True)
        return zip(*pws)[0] if pws else []

    def flush(self, username, password, shadow_pw):
        """Flush the info corresponding to @username, update the pwcache as
        required. Remmeber only call this if the authencation succeeds
        """        
        if username not in self._PW_DB:
            self.initialize(username, password, shadow_pw)
        pws = sorted(self._PW_DB.get(username, []), key=lambda x: x[1], reverse=True)
        # add at most 2 of the last tyoed passwords that meet the strategy requirements
        new_pws = filter(lambda x: strategy1(x[0], password), 
                         self._inmem_cache[username])[-2:] 
        for i,tpw in enumerate(new_pws):
            pws[-i] = (hash_pw(tpw), 1)
        assert len(pws) == CACHE_SIZE
        with open(PWFILE) as pwf:
            self._PW_DB = json.load(pwf)
        self._PW_DB[username] = pws
        self._lock_and_write()
        del self._inmem_cache[username]
        gc.collect()

    def _lock_and_write(self):
        """
        Lock the passwrod file and then write.
        """
        # TODO - proper file locking 
        lock_file = '.__pwlock__'
        while os.path.exists(lock_file):
            time.sleep(0.1)
        with open(lock_file, 'w') as f:
            with open(PWFILE, 'wb') as pwf:
                json.dump(self._PW_DB, pwf, indent=2)
        os.remove(lock_file)



################################################################################
# Different strategies for allowing which passwords can be considered as typos
# and can get plcae in PW_CACHE. For example, 
# 1) allow typoed passwords that are within 1 from the original password
# 2) allow passwords that meet certain pw composition rules
# 3) 
################################################################################
import Levenshtein as lv
def strategy1(tpw, rpw):
    return lv.distance(tpw.lower(), rpw.lower())<=1


