import os, sys
import socket
from subprocess import Popen, PIPE, STDOUT
import time
import json
module_path = os.path.dirname(os.path.abspath(__file__))
CHKPW_EXE = os.path.join(module_path, 'chkpw_new')

daemon_uds = './uds_socket'
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


def check_pw(user, pw, create=1):
    b = False
    try:
        sock.connect(daemon_uds)
        sock.sendall(json.dumps({'user':user, 
                                 'password': pw}))
        d = sock.recv(2)
        return d.strip() == '1'
    except socket.error, msg:
        # print CHKPW_EXE
        # print >>sys.stderr, msg, daemon_uds
        if create:
            os.system('{} {} {} &'.format(CHKPW_EXE, user, pw))
            time.sleep(1)
            b = check_pw(user, pw, create=0)
    finally:
        sock.close()
    return b


def main():
    print "Returned from check_pw:", check_pw(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()
