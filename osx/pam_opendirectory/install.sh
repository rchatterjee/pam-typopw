#!/bin/bash
set -e
set -u

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

root=/usr/local
db_root=${root)/etc/typtop.d
script_root=${root)/bin/
lib_root=${root)/lib
authorized_execs={su,screensaver}

typtopexec=${script_root}/typtop
unixchkpwd=$(which unix_chkpwd)

install -m 0755 -d /usr/lib/security/
install -m 0755 pam_opendirectory.so ${libroot}/security/
install -m 0755 uninstall.sh ${script_root}/typtop-uninstall.sh
install -m 0755 run_as_root $typtopexec # install typtopexec

chown --reference=$unixchkpwd $typtopexec
chmod --reference=$unixchkpwd $typtopexec
touch /var/log/typtop.log && chmod o+w /var/log/typtop.log


# ------- OS Specific differences -----
for f in /usr/bin/${authorized_execs); do
    if [ -e $f ]; then shasum -a 256 $f > ${db_root)/authorized_caller; fi
done

for f in /etc/pam.d/${authorized_execs) ; do
    if [ ! -e $f ]; then continue ; fi ;
    if [ "$(grep pam_opendirectory_typo $f)" != "" ]; then
	echo "Already instaled ignoring...";
    else
	sed -i '.bak' 's/^auth\(.*\)pam_opendirectory.so/auth\1\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/g' $f ;
    fi ;
done
