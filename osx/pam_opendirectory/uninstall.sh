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

for f in /etc/pam.d/${authorized_execs} ; do
    if [ ! -e $f.bak ]; then continue ; fi
    if [ "$(grep pam_opendirectory_typo $f.bak)" != "" ] ; then
	echo "Backup file is wrong. Removing all pam_opendirectory_typo with pam_opendirectory. Checkout the webpage" ;
	sed -i '' 's/^auth\(.*\)\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/auth\1pam_opendirectory.so/g' $f ;
    else
	mv $f.bak $f;
    fi ;
done

rm -rf /var/log/typtop.log /tmp/typtop* ${db_root}
rm -rf /usr/local/bin/typtop* /usr/local/bin/send_typo_log.py
pip -q uninstall --yes typtop
