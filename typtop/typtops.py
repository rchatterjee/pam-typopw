from __future__ import print_function
import os
import sys
import argparse
import requests
import random
import json
from typtop.dbaccess import (
    UserTypoDB,
    call_check, is_user,
    get_time, get_machine_id
)
from typtop.config import (
    NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN,
    WARM_UP_CACHE, VERSION, DISTRO, BINDIR, first_msg,
    LOG_DIR, DB_NAME, TEST,
    SEC_DB_PATH)
from typtop.validate_parent import is_valid_parent
import subprocess

USER = ""
ALLOW_TYPO_LOGIN = True


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


def call_update():
    cmd =  """export PIP_FORMAT=columns;
        pip list --outdated|grep typtop;
        if [ "$?" = "0" ]; then
           pip uninstall -yq typtop
           pip install -U --ignore-installed typtop && typtops.py --init
        else
           echo "Already uptodate! No need to update."
        fi
    """
    os.system(cmd)

THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(THIS_FOLDER, 'typtopserver.crt')


def call_send_logs(args):
    user = args.send_log[0]
    users = [user]
    force = True if (len(args.send_log) > 1 and \
                     args.send_log[1] == 'force') \
        else False
    if user == 'all':  # run for all users
        users = [
            d for d in os.listdir(SEC_DB_PATH)
            if os.path.isdir(os.path.join(SEC_DB_PATH, d))\
            and is_user(d)
        ]
    for user in users:
        typo_db = UserTypoDB(user)
        send_logs(typo_db, force)


def send_logs(typo_db, force=False):
    need_to_send, iter_data = typo_db.get_last_unsent_logs_iter(force)
    logger = typo_db.logger
    if not need_to_send:
        logger.info("No need to send logs now.")
        return

    list_of_logs = list(iter_data)
    install_id = str(typo_db.get_installation_id())
    dbdata = json.dumps(list_of_logs)
    url = 'https://ec2-54-209-30-18.compute-1.amazonaws.com/submit'
    r = requests.post(
        url,
        data=dict(
            # urlsafe-base64 does not have '#'
            uid=install_id.strip() + '#' + str(VERSION),
            data=dbdata,
            test=int(TEST),
        ),
        allow_redirects=True,
        verify=CERT_FILE
    )
    sent_successfully = (r.status_code == 200)
    logger.info("Sent logs status {} ({}) (sent_successfully={})"
                .format(r.status_code, r.text, sent_successfully))
    # deletes the logs that we have sent
    if sent_successfully:
        typo_db.update_last_log_sent_time(
            sent_time=get_time(),
            delete_old_logs=True
        )
        # truncate log file to last 200 lines and look for update if available
        if random.randint(0, 100) <= 20:
            call_update()
        cmd = """
        tail -n500 {0}/{1}.log > /tmp/t.log && mv /tmp/t.log {0}/{1}.log;
        """.format(LOG_DIR, DB_NAME)
        subprocess.Popen(cmd, shell=True)


def initiate_typodb():
    root_only_operation()
    if False:
        pass
    else:
        branch = "master"
        subdir, download_bin, makecmd = '', '', ''
        if DISTRO == 'darwin':
            # TODO: Cleanup this directories. e.g., pam_opendirectory
            subdir = 'csrcs/osx/prebuilt'
            download_bin = "curl -LO"
            makecmd = './install.sh'
        elif DISTRO in ('debian', 'fedora', 'arch'):
            subdir = 'csrcs/linux/'
            download_bin = "wget"
            makecmd = "make && make install"
        download_url = "https://github.com/rchatterjee/pam-typopw/archive/"\
                       "{0}.zip".format(VERSION)
        cmd = """
        cd /tmp/ && {download_bin} {download_url} && unzip -qq -o {version}.zip \
        && cd pam-typopw-{version}/{subdir} && {makecmd};
        cd /tmp && rm -rf {version}.zip pam-typopw*
        """.format(branch=branch, subdir=subdir, download_url=download_url,
                   download_bin=download_bin, makecmd=makecmd, version=VERSION)
        os.system(cmd)

common_auth = {   # Not used
    'debian': '/etc/pam.d/common-auth',
    'fedora': '/etc/pam.d/system-auth',
    'darwin': '',
    'arch'  : '/etc/pam.d/system-auth',
}[DISTRO]


def uninstall_pam_typtop():
    # Last try to send logs
    root_only_operation()

    typtop_uninstall_script = BINDIR + '/typtop-uninstall.sh'
    print(DISTRO)
    subprocess.call(typtop_uninstall_script)

parser = argparse.ArgumentParser("typtop ")
# parser.add_argument(
#     "--user",
#     help="To set the username. Otherwise login user will be the target"
# )

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

parser.add_argument("--id", action="store_true", help="Get Installation id")

# parser.add_argument(
#     "--installid", action="store_true",
#     help="Prints the installation id, which you have to submit while filling up the google form"
# )
parser.add_argument(
    "--send-log", nargs="*", type=str, action="store",
    metavar=("user", "force"),
    help="Send the logs to the server"
)

parser.add_argument(
    "--status", action="store", nargs="+",
    metavar="user",
    help="Prints current states of the typo-tolerance."\
    "Needs a username as argument."
)

parser.add_argument(
    "--uninstall", action="store_true",
    help="Uninstall TypToP from your machine. Will delete all the data related to TypTop too."
)

# parser.add_argument(
#     "--reinit", action="store_true",
#     help="To re-initiate the DB, especially after the user's pw has changed"
# )

parser.add_argument(
    "--update", action="store_true",
    help="Updates TypTop to the latest released version"
)

parser.add_argument(
    "--check", action="store", nargs=3,
    help="(INTERNAL FUNCTION. PLEASE DON'T CALL THIS.)"
)

parser.add_argument(
    "--debug", action="store_true",
    help="Prepare report for debugging"
)


def main():
    args = parser.parse_args()
    if len(sys.argv) <=1:
        print(parser.print_help())
        sys.exit(0)

    # ITS IMPORTANT THIS ONE WILL BE FIRST
    # if args.user:
    #     global USER
    #     USER = args.user
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
            print(first_msg, file=sys.stderr)
            print("Initializing the typo database..")
            initiate_typodb()

        # if args.reinit:
        #     print("RE-initiating pam_typtop")
        #     initiate_typodb(RE_INIT=True)

        if args.status :
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
            call_update()

        if args.id:
            print("Install-id:", get_machine_id())

        if args.debug:
            p = subprocess.Popen(
                'pip show numpy', shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            numpypath = ''
            for l in p.stdout:
                l = l.strip().split(': ', 1)
                if l[0] == 'Location':
                    numpypath = l[1]
                    break
            print("Is numpy in path: {}".format(numpypath in sys.path))
            proc = subprocess.Popen(
                # TODO: Add numpy path constraint

                """
                set -x
                set -u

                users
                # su $USER -c "which su"
                # <enter correct password>
                # if [ $? -neq 0 ]; then exit; else "echo password incorrect"; fi
                typtop --status $USER
                sudo ls -altrh  /usr/local/etc/typtop.d/$USER/typtop.json
                ls -altrh $(which su) $(which typtop)
                python -c "import pwd; print pwd.getpwnam('$USER')"
                tail -n50 /var/log/typtop.log
                """, shell=True,
                stdout=subprocess.PIPE,
                # stderr=subprocess.STDOUT
                stderr=sys.stdout.fileno()
            )
            print(proc.stdout.read())

        if args.check:
            # ensure the parent is pam_opendirectory_typo.so
            assert is_valid_parent()
            failed, user, pw = args.check
            ret = call_check(failed, user, pw)
            sys.stdout.write(str(ret))
            # if ret==0:
            #     p = subprocess.Popen([SEND_LOGS_SCRIPT, user])
        if args.send_log:
            call_send_logs(args)

    except AbortSettings:
        print("Settings' change had been aborted.")


if __name__ == '__main__':
    main()
