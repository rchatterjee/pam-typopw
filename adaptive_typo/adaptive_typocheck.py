#!/usr/bin/python

"""Old script, when I was thinking of adaptive typo will be a daemon
running to capture all the password in one session. But I realize that's
overkill for the very very narrow threat model. Let's do it in simple way.

"""

import sys
import os
import crypt # , getpass, pwd
import socket
import string
import spwd
from pwcache import PwCache
########## CONSTANTS ##################################################

"""
Each user's entry will be as follows; key=username
{
'user1': [(real_pw_hash, count), (typopw_1_hash, count_1), (typopw_2_hash, count_2),
          (typopw_3_hash, count_3)]
}
"""
pwcache = PwCache()

def log(*args):
    LOG_FL.write("{}: {}\n".format(time.time(), args))

def read_shadow_file(username):
    cryptedpasswd = spwd.getspnam(username)[1]
    if not cryptedpasswd:
        raise ValueError("UserNotFound")
    return cryptedpasswd

def write_user_data(new_user_dict):
    try:
        with open(PWFILE) as pwf:
            D = json.load(pwf).update(new_user_dict)
        with open(PWFILE, 'wb') as pwfw:
            json.dump(D, pwfw, indent=2)
        return 0
    except:
        log("Something went wrong. Can you check the file {}".format(PWFILE))
        return -1


def login(username, password):
    cryptedpasswd = pwd.getpwnam(username)[1]
    if cryptedpasswd:
        if cryptedpasswd == 'x' or cryptedpasswd == '*':
            raise NotImplementedError(
                "Sorry, currently no support for shadow passwords")
        return crypt.crypt(password, cryptedpasswd) == cryptedpasswd
    else:
        log("user={!r} not found".format(username))
        raise Exception("UserNotFound")

def authenticate(username, password):
    """
    The Magic function!
    """
    r = get_user_data(username)
    orig_shadow = ''
    if r:
        orig_shadow = r[0][0]
        for shadow_pw in shadow_pw,c in sorted(r, key=lambda x: x[1], reverse=True):
            ret = test_equality(password, shadow_pw)
            if ret:
                if r[0][0] == shadow_pw: # authenticated with original password
                    flush_inmem_cache(username)
                return ret
    try:
        shadow_pw = read_shadow_file(username)
        if orig_shadow and shadow_pw != orig_shadow:
            # real password has changed, start afresh, purge all cache
            
        ret = test_equality(password, shadow_pw)
        if not ret: # if the authetication fails, store the wrong entry for 30 sec
            put_in_inmem_cache(usernme, test_equality(password))
    except IOError:
        log("I could not open the shadow file")
        return False
    except ValueError: 
        log("I could not find the user {!r}.".format(username))
        return False
            
    log("Authenricating {}: {}".format(username, ret))
    return ret

    

server_address = './uds_socket'
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
def daemon():
    """The first copy of this program (p0) stays alive for ~30 sec till
    the last entry of a password or login succeeds, whichever is
    earlier.  The subsequent copies of this function just, passes on
    the data to the first process (p0). Using a unix socket.
    """
    try:
        log("Starting daemon..")
        sock.bind(server_address)
        sock.listen(5) # Can listen to at most 5 clients 
        sock.settimeout(100) # die after 30 second
        while True: 
            connection, client_addr = sock.accept()
            data = connection.recv(100)
            log("Received data: {}".format(data))
            json_d = json.loads(data)
            log(json_d)
            # authenticate 
            b = int(authenticate(json_d.get('user', ''), 
                                 json_d.get('password', '')))
            log("Returning b")
            connection.sendall('{}\n'.format(b))
            connection.close()
    except ValueError, e:
        log("ERROR", "Could not json.loads", data)
        pass
    except socket.timeout, e:
        pass
    finally:
        shutdown()

def shutdown():
    log("Killing the server. Did not receive any response")
    if os.path.exists(server_address):
        os.unlink(server_address)
 

def test_equality(cleartextpw, cryptedpw=""):
    """comparse the cleartextpw with the crypted password. If crypted
    password is "", then it creates a random salt, encrypts (hashses
    SHA512, salt size 83) it and returns it back.

    """
    if not cryptedpw:
        return crypt.crypt(cleartextpw, '$6${}$'.format(salt(83)))
    else:
        if cryptedpw == 'x' or cryptedpw == '*':
            raise NotImplementedError(
                "Sorry, currently no support for shadow passwords")

        return crypt.crypt(cleartextpw, cryptedpw) == cryptedpw
    
def main(username, pw):
    """given a username and password checks whether or not the password
    is correct.
    """
    pass

if __name__ == "__main__":
    # print sys.argv
    # print authenticate(sys.argv[1], sys.argv[2])
    daemon()
    # udata = read_shadow_file(sys.argv[1])
    # u, p = udata[0], udata[1]
    # print test_equality(p, sys.argv[2])
    # print test_equality(sys.argv[2], p)
    # h = test_equality(sys.argv[2])
    # print test_equality(sys.argv[2], h)
