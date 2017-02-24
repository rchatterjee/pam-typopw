#!/bin/bash
set -e
set -u
set -x

echo "Installing Typtop..."
platform=$(uname)
if [[ "$platform" == "Linux" ]]; then
    pam_mod=pam_unix.so
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit
    fi
    unixchkpwd=$(which unix_chkpwd)
elif [[ "$platform" == "Darwin" ]]; then
    pam_mod=pam_opendirectory.so
    unixchkpwd=$(which su)
fi

echo "Found platform = ${platform}, using ${pam_mod}"

root=/usr/local
db_root=${root}/etc/typtop.d
script_root=${root}/bin/
lib_root=${root}/lib
authorized_execs={su,screensaver}

typtopexec=${script_root}/typtop


install -m 0755 -d ${root}/lib/security/
install -m 0771 -d ${db_root}  # owned by root, and group, others cannot even read
install -m 0755 pam_typtop.so ${lib_root}/security/
install -m 0755 uninstall.sh ${script_root}/typtop-uninstall.sh
install -m 0755 run_as_root $typtopexec # install typtopexec

if [[ "$platform" == "Darwin" ]]; then
    savemod=$(stat -f "%p" $unixchkpwd)
    saveown=$(stat -f "%Su:%Sg" $unixchkpwd)
    chown $saveown $typtopexec
    chmod $savemod $typtopexec
    chown $saveown ${db_root}
else
    chown --reference=$unixchkpwd $typtopexec
    chmod --reference=$unixchkpwd $typtopexec
    chown --reference=$unixchkpwd ${db_root}
fi

send_logs_script=$(which send_typo_log.py)
touch /var/log/typtop.log && chmod o+w /var/log/typtop.log
(crontab -l | sed '/send_typto_logs.py/d';
 echo "00 */6 * * * ${send_logs_script} all >>/var/log/send_typo.log 2>&1") | crontab -

# ------- OS Specific differences -----
if [ -d "/etc/pam.d/" ]; then
    for f in /etc/pam.d/*.orig; do
        if [ -e "$f" ]; then
            echo "Already backed up PAM config files at /etc/pam.d/*.orig. Have you already installed?"
            exit
        fi
    done
    if [ -e "/etc/pam.d/*.orig" ]; then
        exit
    fi
    pushd /etc/pam.d > /dev/null
    sed -i.orig "s/^auth\W*.*${pam_mod}.*/auth\tinclude\ttyptop-auth/g" *
    popd > /dev/null
    echo "Configuring PAM to use typtop with /etc/pam.d/ files"
    cp typtop-auth /etc/pam.d/
elif [ -e "/etc/pam.conf" ]; then
    cp typtop-auth /etc/pam-typtop-auth
    sed -i.orig "s/^auth\W*.*${pam_mod}/auth\tinclude\tpam-typtop-auth/g" /etc/pam.conf
    echo "Configuring /etc/pam.conf to use typtop"
else
    echo "Could not determine where to install pam config files, please do so manually"
fi

echo "--"
echo "Contrats!! Looks like installation is successful. Hurray :)"
