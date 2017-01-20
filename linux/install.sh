#!/bin/sh

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

install -m 0755 -d /usr/lib/security/
install -m 0755 pam_typtop.so /usr/lib/security/

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
    cp typtop-auth /etc/pam.d/
    pushd /etc/pam.d > /dev/null
    sed -i.orig 's/auth\W*required\W*pam_unix.so$/auth\tsubstack\ttyptop-auth/g' *
    popd > /dev/null
    echo "Configuring PAM to use typtop with /etc/pam.d/ files"
elif [ -e "/etc/pam.conf" ]; then
    cp typtop-auth /etc/pam-typtop-auth
    sed -i.orig 's/auth\W*required\W*pam_unix.so$/auth\tsubstack\tpam-typtop-auth/g' /etc/pam.conf
    echo "Configuring /etc/pam.conf to use typtop"
else 
    echo "Could not determine where to install pam config files, please do so manually"
fi
