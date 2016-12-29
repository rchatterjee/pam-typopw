#!/usr/bin/env python

import os
import sys
import requests
import json
import pwd
from typtop.dbaccess import UserTypoDB, get_time
from typtop.config import LOG_DIR, VERSION, SEC_DB_PATH, DB_NAME
from typtop.dbutils import logger

# Disable this weird warning. (Future TODO - deal with this.)
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

# note - there's no way this script will be called
# without the DB being initialized, because we call it
# AFTER a SUCCESSFUL login

THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(THIS_FOLDER, 'typtopserver.crt')

def send_logs(typo_db, force=False):
    need_to_send, iter_data = typo_db.get_last_unsent_logs_iter(force)
    last_time = 0
    list_of_logs = []
    if not need_to_send:
        return

    list_of_logs = list(iter_data)
    install_id = str(typo_db.get_installation_id())
    dbdata = json.dumps(list_of_logs)
    url='https://ec2-54-209-30-18.compute-1.amazonaws.com/submit'
    r = requests.post(
        url,
        data=dict(
            uid=install_id.strip() + '#' + str(VERSION), # urlsafe-base64 does not have '#'
            data=dbdata,
            test=0,
        ),
        allow_redirects=True,
        verify=CERT_FILE
    )
    logger.info("Sent logs status {}, {}".format(r.status_code, r.text))
    sent_successfully = (r.status_code == requests.codes.all_good)
    # deletes the logs that we have sent
    if sent_successfully:
        typo_db.update_last_log_sent_time(
            sent_time=get_time(),
            delete_old_logs=True
        )
        # truncate log file to last 500 lines
        cmd = """
        tail -n500 {0}/{1}.log > /tmp/t.log && mv /tmp/t.log {0}/{1}.log
        """.format(LOG_DIR, DB_NAME)
        os.system(cmd)

def main():
    assert len(sys.argv) > 1
    user = sys.argv[1]
    users = [user]
    force = True if (len(sys.argv)>2 and sys.argv[2] == 'force') \
            else False
    if user == 'all': # run for all users
        users = [d for d in os.listdir(SEC_DB_PATH) if os.path.isdir(os.path.join(SEC_DB_PATH, d))]
    for user in users:
        typo_db = UserTypoDB(user)
        send_logs(typo_db, force)

if __name__ == '__main__':
    main()
