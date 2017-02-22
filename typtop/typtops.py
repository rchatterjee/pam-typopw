from __future__ import print_function
import os, sys
import argparse
from typtop.dbaccess import (
    UserTypoDB,
    call_check
)
from typtop.config import (
    SEC_DB_PATH, NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN,
    WARM_UP_CACHE, VERSION, GROUP, DISTRO, BINDIR
)
from typtop.validate_parent import is_valid_parent
import subprocess

USER = ""
SEND_LOGS_SCRIPT = '{}/send_typo_log.py'.format(BINDIR)
if not os.path.exists(SEND_LOGS_SCRIPT):
    SEND_LOGS_SCRIPT = '/usr/bin/send_typo_log.py'
    if not os.path.exists(SEND_LOGS_SCRIPT):
        SEND_LOGS_SCRIPT = 'send_typo_log.py'

ALLOW_TYPO_LOGIN = True
GITHUB_URL = 'https://github.com/rchatterjee/pam-typopw' # URL in github repo

first_msg = """\n\n
  /  |                          /  |
 _$$ |_    __    __   ______   _$$ |_     ______    ______
/ $$   |  /  |  /  | /      \ / $$   |   /      \  /      \\
$$$$$$/   $$ |  $$ |/$$$$$$  |$$$$$$/   /$$$$$$  |/$$$$$$  |
  $$ | __ $$ |  $$ |$$ |  $$ |  $$ | __ $$ |  $$ |$$ |  $$ |
  $$ |/  |$$ \__$$ |$$ |__$$ |  $$ |/  |$$ \__$$ |$$ |__$$ |
  $$  $$/ $$    $$ |$$    $$/   $$  $$/ $$    $$/ $$    $$/
   $$$$/   $$$$$$$ |$$$$$$$/     $$$$/   $$$$$$/  $$$$$$$/
          /  \__$$ |$$ |                          $$ |
          $$    $$/ $$ |                          $$ |
           $$$$$$/  $$/                           $$/
Hello!

Thanks for installing TypToP (version: {version}).  This software
attaches a new pluggable authentication module (PAM) to some of your
common authentication processes, such as su, login, screensaver etc.,
and observes for password typing mistakes. It records your frequent
typing mistakes, and enable logging in with slight vairations of your
actual login password that are frequent and safe to do so.

This is a research prototype, and we are collecting some anonymous
non-sensitive data about your password typing patterns to verify our
design. The details of what we collect, how we collect and store, and
the security blueprint of this software can be found in the GitHub
page: {url}.  The participation in the study is completely voluntary,
and you can opt out at any time while still keep using the software.

Checkout other options (such as opting out of the study) of the
utility script typtop by running:

$ typtops.py --help

Note, You have to initiate this for each user who intend to use the
benefit of adaptive typo-tolerant password login.
""".format


class AbortSettings(RuntimeError):
    pass

def _get_login_user():
    # gets the username of the logging user
    pp = subprocess.Popen('who', stdout=subprocess.PIPE)
    output = pp.stdout.read()
    first_line = output.splitlines()[0]
    user = first_line.split()[0]
    return user


def _get_username():
    # trying to go over the problem of
    if USER:
        print("Designated user: {}".format(USER))
        return USER
    uid = os.getuid()
    is_root = uid == 0
    user = _get_login_user()
    if is_root:
        r = raw_input("Setting will be done for login user: {}.\n"
                      "Please confirm. (Yn) ".format(user))
        abort = r and r.lower() == "n"
        if abort:
            raise AbortSettings()
    else:
        print("Designated user: {}".format(user))
    return user


def _get_typoDB():
    user = _get_username()
    try:
        typoDB = UserTypoDB(user)
    except Exception as e:
        print(
            "It seems you have not initialized the db. Try running"\
            " \"sudo {} --init\" to initialize the db.\nThe error "\
            "I ran into is the following:\n{}"
            .format(sys.argv[0], e)
        )
        return None
    if not typoDB.is_typtop_init():
        raise Exception("{}:{} not initiated".format(
            str(typoDB),
            typoDB.get_db_path())
        )
    return typoDB


def root_only_operation():
    if os.getuid() != 0:
        print("ERROR!! You need root privilege to run this operation")
        raise AbortSettings


def initiate_typodb(RE_INIT=False):
    # ValueError(
    #     "You should not require to call this. "
    #     "Something is wrong!! Try re-installing the whole system"
    # )
    root_only_operation()
    # user = _get_username()
    # try:
    #     # checks that such a user exists:
    #     _ = pwd.getpwnam(user).pw_dir
    # except KeyError as e:
    #     print("Error: {}".format(e.message))
    #     print("Hint: The user ({}) must have an account in this computer."\
    #           .format(user))
    #     print("Hint 2: It's not a registration. User the username for "\
    #           "your account in the computer.")
    if False:
        pass
    else:
        branch = "master"
        subdir, download_bin, makecmd = '', '', ''
        if DISTRO == 'darwin':
            # TODO: Cleanup this directories. e.g., pam_opendirectory
            subdir = 'osx/pam_opendirectory'
            download_bin = "curl -LO"
            makecmd = 'make && make install'
        elif DISTRO in ('debian', 'fedora'):
            subdir = 'linux/'
            download_bin = "wget"
            makecmd = "make && make install"
        cmd = """
        cd /tmp/ && {download_bin} https://github.com/rchatterjee/pam-typopw/archive/{branch}.zip && unzip {branch}.zip \
        && cd pam-typopw-{branch}/{subdir} && {makecmd};
        cd /tmp && rm -rf {branch}.zip pam-typopw*

        mkdir -p {sec_db_path} && chown -R root:{group} {sec_db_path}; \
        chmod -R g+w {sec_db_path} && chmod -R o-rw {sec_db_path};
        touch /var/log/typtop.log && chmod o+w /var/log/typtop.log;

        (crontab -l; echo "00 */6 * * * {send_logs} all >>/var/log/send_typo.log 2>&1") | sort - | uniq - | crontab -
        """.format(branch=branch, subdir=subdir,
                   download_bin=download_bin, sec_db_path=SEC_DB_PATH,
                   group=GROUP, send_logs=SEND_LOGS_SCRIPT, makecmd=makecmd)
        print(cmd)
        os.system(cmd)

common_auth = {   # Not used
    'debian': '/etc/pam.d/common-auth',
    'fedora': '/etc/pam.d/system-auth',
    'darwin': ''
}[DISTRO]


def uninstall_pam_typtop():
    # Last try to send logs
    root_only_operation()
    typtop_uninstall_script = BINDIR + '/typtop-uninstall.sh'
    print(DISTRO)
    subprocess.call(typtop_uninstall_script)

parser = argparse.ArgumentParser("typtop ")
parser.add_argument(
    "--user",
    help="To set the username. Otherwise login user will be the target"
)
parser.add_argument(
    "--init", action="store_true",
    help="To initialize the DB. You have to run this once you install pam_typtop"
)

parser.add_argument(
    "--allowtypo", type=str.lower, choices=['yes','no'],
    help='Allow login with typos of the password'
)

parser.add_argument(
    "--allowupload", type=str.lower, choices=['yes', 'no'],
    help="Allow uploading the non-sensitive anonymous "\
    "data into the server for research purposes."
)

parser.add_argument(
    "--installid", action="store_true",
    help="Prints the installation id, which you have to submit while filling up the google form"
)

parser.add_argument(
    "--status", action="store", nargs="*",
    help='Prints current states of the typo-tolerance. Needs a username as argument.'
)

parser.add_argument(
    "--uninstall", action="store_true",
    help="Uninstall TypToP from your machine. Will delete all the data related to TypTop too."
)

parser.add_argument(
    "--reinit", action="store_true",
    help="To re-initiate the DB, especially after the user's pw has changed"
)

parser.add_argument(
    "--update", action="store_true",
    help="Updates TypTop to the latest released version"
)

parser.add_argument(
    "--check", action="store", nargs=3,
    help="(INTERNAL FUNCTION. PLEASE DON'T CALL THIS.)"
)

def main():
    args = parser.parse_args()
    if len(sys.argv) <=1:
        print(parser.print_help())
        sys.exit(0)

    # ITS IMPORTANT THIS ONE WILL BE FIRST
    if args.user:
        global USER
        USER = args.user
        # print("User settings have been set to {}".format(USER))
    try:
        # root_only_operation()
        if args.allowtypo:
            typoDB = _get_typoDB()
            if args.allowtypo == "no":
                typoDB.allow_login(False)
                print(
                    """
Turning OFF login with typos. The software will still monitor your
typos and build cache of popular typos. You can switch on this
whenever you want.
                    """)  # :{}".format(typoDB.is_allowed_login())
            elif args.allowtypo == "yes":
                print("Turning ON login with typos...",)
                typoDB.allow_login(True)

        if args.allowupload:
            typoDB = _get_typoDB()
            if args.allowupload == "yes":
                typoDB.allow_upload(True)
                print("Uploading data is enabled. You are awesome. Thanks!!")
            elif args.allowupload == "no":
                typoDB.allow_upload(False)
                print("Uploading data is disabled.  :( :'( :-(!")
                print("Thanks for using the software anyway.")

        if args.init:
            print(first_msg(url=GITHUB_URL, version=VERSION), file=sys.stderr)
            print("Initializing the typo database..")
            initiate_typodb()

        if args.reinit:
            print("RE-initiating pam_typtop")
            initiate_typodb(RE_INIT=True)

        if args.status:
            users = args.status
            if not users:
                users.add(_get_username())
            for user in users:
                typoDB = UserTypoDB(user)
                print("\n** TYPO-TOLERANCE STATUS **\n")
                print(">> User: {}".format(user))
                print("\tLogin with typos: {}".format(typoDB.is_allowed_login()))
                print("\tParticipate in the study: {}"\
                      .format(typoDB.is_allowed_upload()))
                print("\tIs enough logins to allow typos: {}"\
                      .format(typoDB.check_login_count(update=False)))
                print("\tInstall Id: {}".format(typoDB.get_installation_id().strip()))
                print("\tSoftware Version: {}".format(VERSION))
                print("\tNum entries before typo-login allowed: {}".format(NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN))
                print("\tWarmup cache: {}".format(WARM_UP_CACHE))

        if args.uninstall:
            r = raw_input("Uninstalling pam_typtop. Will delete all the "
                          "databases.\nPlease confirm. (yN)")
            if r and r.lower() == "y":
                uninstall_pam_typtop()

        if args.update:  # delete all old data
            subprocess.call(
                "pip install -U typtop && typtops.py --init",
                shell=True
            )

        if args.check:
            # ensure the parent is pam_opendirectory_typo.so
            assert is_valid_parent()
            failed, user, pw = args.check
            ret = call_check(failed, user, pw)
            sys.stdout.write(str(ret))
            # if ret==0:
            #     p = subprocess.Popen([SEND_LOGS_SCRIPT, user])

    except AbortSettings:
        print("Settings' change had been aborted.")


if __name__ == '__main__':
    main()
