#!/usr/bin/python
import sys
import os
import crypt # , getpass, pwd
import socket
import string
import time
import json

PWFILE = "pwcache_file.json"
CAHCE_SIZE = 11

# This file is a dictionary from username to the list of apasswords
# LOG_FL = sys.stderr if __name__ == "__main__" else open('typoauth.log', 'a+')
LOG_FL = open('typoauth.log', 'a+')
def log(*args):
    LOG_FL.write("{}: {}\n".format(time.time(), args))

in_mem_db = {}

def read_shadow_file(username):
    shadow_file = '/etc/shadow'
    with open(shadow_file, 'rb') as shf:
        for line in shf:
            if line.startswith(username):
                return line.split(':')[1]
    raise ValueError("UserNotFound")

def get_user_data(username):
    try:
        with open(PWFILE) as pwf:
            return json.load(pwf).get(username, {})
    except IOError, e:
        log(e)
        return {}

def write_user_data(cahce_dict):
    try:
        with open(PWFILE) as pwf:
            D = json.load(pwf).update(new_pw_dict)
        with open(PWFILE, 'wb') as pwfw:
            json.dump(D, pwfw, indent=2)
        return 0
    except:
        log("Something went wrong. Can you check the file {}".format(PWFILE))
        return -1
        
def salt(n=83):
    """returns n charater long salt, from [a-zA-Z0-9]
    """
    s = string.ascii_letters + string.digits
    return ''.join(s[ord(t) % len(s)] for t in os.urandom(n))

def login():
    username = raw_input('Python login:')
    cryptedpasswd = pwd.getpwnam(username)[1]
    if cryptedpasswd:
        if cryptedpasswd == 'x' or cryptedpasswd == '*':
            raise NotImplementedError(
                "Sorry, currently no support for shadow passwords")
        cleartext = getpass.getpass()
        return crypt.crypt(cleartext, cryptedpasswd) == cryptedpasswd
    else:
        return 1

def authenticate(username, password):
    """
    The Magic function!
    """
    r = get_user_data(username)
    if r:
        shadow_pw = r.get('pw')
    else:
        try:
            shadow_pw = read_shadow_file(username)
        except IOError:
            log("I could not open the shadow file")
            return False
        except ValueError: 
            log("I could not find the user {!r}.".format(username))
            return False
    ret = test_equality(password, shadow_pw)
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
        sock.listen(1) # check this 1
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
