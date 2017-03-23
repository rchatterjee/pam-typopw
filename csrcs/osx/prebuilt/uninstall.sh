#!/bin/bash
# set -e
# set -u
# set -x

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

root=/usr/local
db_root=${root}/etc/typtop.d
script_root=${root}/bin/
lib_root=${root}/lib

typtopexec=$(which typtop) || ${script_root}/typtop
authorized_execs=(su screensaver)
send_logs_script="${typtopexec} --send-log"

# Send the log last time
send_log() {
    ${send_logs_script} all force
}
send_log

for f in ${authorized_execs[@]} ; do
    f=/etc/pam.d/$f
    if [ ! -e $f.bak ]; then continue ; fi
    if [ "$(grep pam_opendirectory_typo $f.bak)" != "" ] ; then
	    echo "Backup file is wrong. Removing all pam_opendirectory_typo with pam_opendirectory. Checkout the webpage" ;
	    sed -i '' 's/^auth\(.*\)\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/auth\1pam_opendirectory.so/g' $f ;
    else
	    mv $f.bak $f;
    fi
done

rm -rf /var/log/typtop.log /tmp/typtop* ${db_root}
rm -rf ${script_root}/typtop* ${script_root}/send_typo_log.py

crontab -l | sed -E '/send_typto_logs.py|typtop/d' | crontab -

pip freeze | grep typtop
if [[ $? == 0 ]]; then
    pip -q uninstall --yes typtop word2keypress zxcvbn zxcvbn-python >&/dev/null
fi
