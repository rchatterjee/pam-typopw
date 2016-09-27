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
        raise Exception("{}:{} not initiated".format(
            str(typoDB),
            typoDB.get_db_path(user))
        )
    return typoDB

parser = argparse.ArgumentParser("Change settings of the adaptive_typo module.")
parser.add_argument(
    "--allowtypo", type=str.lower, choices=['yes','no'],
    help='Allow login with typos of the password'
)
parser.add_argument(
    "--status", action="store_true",
    help='Prints current states of the typotolerance.'
)
parser.add_argument(
    "--allowupload", type=str.lower, choices=['yes', 'no'],
    help="Allow uploading the non-sensive annonymous data into the server for research purposes."
)
parser.add_argument(
    "--installid", action="store_true",
    help="Prints the installation id, which you have to submit while filling up the google form"
)

typoDB = _get_typoDB()
args = parser.parse_args()
if args.allowtypo:
    if args.allowtypo == "no":
        # typoDB.allow_login(True)
        print "Turning OFF login with typos. The software will still monitor\n"\
            "your typos and build cache of popular typos. You can switch on this\n"\
            "whenever you want"# :{}".format(typoDB.is_allowed_login())
    elif args.allowtypo == "yes":
        print "Turning ON login with typos...",
        # typoDB.allow_login(False)

if args.allowupload:
    if args.allowupload == "yes":
        # allowupload(False)
        print "Uploading data is enabled. You are awesome. Thanks!!"
    elif args.allowupload == "no":
        # allowupload(True)
        print "Uploading data is disabled.  :( :'( :-(!"
    print "Thanks for using the software anyway."

if args.status:
    print("Login with typos: {}".format(typoDB.is_allowed_login()))
    print("Participate in the study: {}")#.format(typoDB.allowupload()))


