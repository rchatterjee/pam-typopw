#!/usr/local/bin/python
import os
import sys
import requests
import json
import pwd
from typtop.dbaccess import UserTypoDB, get_time
from typtop.config import LOG_DIR, DB_NAME
from typtop.dbutils import logger

# note - there's no way this script will be called
# without the DB being initialized, because we call it
# AFTER a SUCCESSFUL login
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
            uid=install_id,
            data=dbdata,
            test=0
        ),
        allow_redirects=True,
        verify=False
    )
    logger.info("Sent logs status {}, {}".format(r.status_code, r.text))
    sent_successfully = (r.status_code == requests.codes.all_good)
    # deletes the logs that we have sent
    if sent_successfully:
        typo_db.update_last_log_sent_time(
            sent_time=get_time(),
            delete_old_logs=True
        )
        # with open('{}/{}.log'.format(LOG_DIR, DB_NAME), 'w') as f:
        #     pass

if __name__ == '__main__':
    assert len(sys.argv) > 1
    user =  sys.argv[1]
    typo_db = UserTypoDB(user)
    force = False
    if len(sys.argv)>2 and sys.argv[2] == 'force':
        force = True
    send_logs(typo_db, force)
