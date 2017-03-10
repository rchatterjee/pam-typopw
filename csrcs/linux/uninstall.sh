#!/bin/bash
set -e
set -u

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

root=/usr/local
db_root=${root}/etc/typtop.d
script_root=${root}/bin/
lib_root=${root}/lib
authorized_execs={su,screensaver}

# Send the log last time
send_logs_script="$(which typtop) --send-log"
${send_logs_script} all force

if [ -d "/etc/pam.d/" ]; then
    rm -rf /etc/pam.d/typtop-auth*
    pushd /etc/pam.d/ >/dev/null
    for f in *.orig; do
        if [ -e $f ]; then
            # echo "mv $f ${f%.*}"
            mv $f ${f%.*}
        fi
    done
    popd > /dev/null

    # sed -i.bak 's/auth\tsubstack\ttyptop-auth/auth\trequired\tpam_unix.so/g'
    rm -f /etc/pam.d/typtop-auth
    echo "Reverting to original files"
elif [ -e "/etc/pam.conf" ]; then
    mv /etc/pam.conf.orig /etc/pam.conf
    rm -f /etc/pam-typtop-auth
    echo "Reverting to original files"
else
    echo "Could not determine where to install pam config files, please do so manually"
fi

rm -rf ${db_root} ${root}/lib/security/pam_typtop.so
rm -rf /var/log/typtop.log /tmp/typtop*
rm -rf ${script_root}/typtop* ${script_root}/send_typo_log.py

crontab -l | sed -E '/send_typto_logs.py|typtop/d' | crontab -

pip freeze | grep typtop
if [[ $? == 0 ]]; then
    pip -q uninstall --yes typtop word2keypress zxcvbn zxcvbn-python >&/dev/null
fi
