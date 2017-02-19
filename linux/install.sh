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

typtopexec=${script_root}/typtop
unixchkpwd=$(which unix_chkpwd)

install -m 0755 -d /usr/local/lib/security/
install -m 0755 pam_typtop.so ${lib_root}/security/
install -m 0755 uninstall.sh ${script_root}/typtop-uninstall.sh
install -m 0755 run_as_root $typtopexec # install typtopexec

chown --reference=$unixchkpwd $typtopexec
chmod --reference=$unixchkpwd $typtopexec
touch /var/log/typtop.log && chmod o+w /var/log/typtop.log

platform=$(uname)
if [[ "$platform" == "Linux" ]]; then
    pam_mod=pam_unix.so
elif [[ "$platform" == "Darwin" ]]; then
    pam_mod=pam_opendirectory.so
fi

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
