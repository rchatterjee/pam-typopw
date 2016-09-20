import os
import pwd
import argparse
from adaptive_typo.typo_db_access import UserTypoDB


def _get_username():
    # change to login user?
    user =  pwd.getpwuid(os.getuid()).pw_name
    print user
    return user

def _get_typoDB():
    user = _get_username()
    typoDB = UserTypoDB(user)
    if not typoDB.is_typotoler_init():
        raise Exception("{}:{} not initiated".format(str(typoDB),typoDB.get_DB_path()))
    return typoDB

parser = argparse.ArgumentParser()
parser.add_argument("--turn",type=str,choices=['off','on'],help='dis/activate typotoler')
parser.add_argument("status",help='prints typotoler status')

typoDB = _get_typoDB()
args = parser.parse_args()
if args.turn == "on":
    typoDB.allow_login()
    print "typotoler set to ON"# :{}".format(typoDB.is_allowed_login())
if args.turn == "off":
    typoDB.disallow_login()
    print "typotoler set to OFF" #:{}".format(typoDB.is_allowed_login())

if args.status:
    print "typotoler is set to {}".format(typoDB.is_allowed_login())
