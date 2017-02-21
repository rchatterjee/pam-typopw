#!/bin/bash
set -e
set -u
set -x

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

root=/usr/local
db_root=${root}/etc/typtop.d
script_root=${root}/bin/
lib_root=${root}/lib
authorized_execs=(su screensaver)

# Send the log last time
${script_root}/send_typo_log.py $USER force

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
pip -q uninstall --yes typtop
