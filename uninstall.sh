#!/bin/bash
set -e
set -u

if [ "$(id -u)" != "0" ]; then 
    echo "You need root priviledge to run this script."
    exit;
fi

# remove pip libraries
# pip uninstall dawg pwmodels typofixer

# remove dawg

common_auth_file=/etc/pam.d/common-auth
if [ -e ${common_auth_file}.orig ]; then
    mv ${common_auth_file}.orig ${common_auth_file}
fi
bindir=/usr/local/bin/
rm -rf ${bindir}/pam_typotolerant.py $bindir/chkpw $bindir/send_typo_log.py
rm -rf ${bindir}/typtop
rm -rf /etc/pam_typtop/
rm -rf /etc/pam.d/typo_auth
# pip uninstall typtop
if [ -e ffile.txt ]; then
    cat ffile.txt | xargs rm -i
    rm -rf ffile.txt
fi

apt-get remove libpam-python libdawgdic-dev
