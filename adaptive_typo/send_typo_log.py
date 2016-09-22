from adaptive_typo.typo_db_access import UserTypoDB #,LastSent
import json
import pwd
import os
import requests


# note - there's no way this script will be called
# without the DB being initialized, because we call it
# AFTER a SUCCESSFUL login

user =  pwd.getpwuid(os.getuid()).pw_name
t_db = UserTypoDB(user)
#t_db.update_last_log_sent_time('0') # TODO REMOVE ! 
need_to_send, iter_data = t_db.get_last_unsent_logs_iter()
#need_to_send = True
#iter_data = range(100000)
last_time = 0
list_of_logs = []
if need_to_send:
    for row in iter_data:
        # print "row to send:{}".format(row)
        list_of_logs.append(row)
        last_time = min(last_time,row['ts'])
        
    install_id = str(t_db.get_installation_id())
    dbdata = json.dumps(list_of_logs)
    url='https://ec2-54-209-30-18.compute-1.amazonaws.com/submit'
    r = requests.post(
        url,
        data=dict(
            uid=install_id,
            data=dbdata,
            test=1
        ),
        allow_redirects=True,
        verify=False
    )
    print r.status_code
    print r.text
    
    # t_db.update_last_log_sent_time(last_time)
