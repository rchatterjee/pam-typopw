#!/bin/bash
set -e
set -u
set -x

root=/usr/local
db_root=${root}/etc/typtop.d
script_root=${root}/bin/
lib_root=${root}/lib
authorized_execs=(su screensaver)

typtopexec=${script_root}/typtop

platform=$(uname)
unixchkpwd=$(which su)

install -m 0755 -d ${lib_root}/security/
install -m 0771 -d $db_root
install -m 0755 pam_opendirectory.so ${lib_root}/security/
install -m 0755 uninstall.sh ${script_root}/typtop-uninstall.sh
install -m 0755 run_as_root $typtopexec # install typtopexec

savemod=$(stat -f "%p" $unixchkpwd)
saveown=$(stat -f "%Su:%Sg" $unixchkpwd)

chown $saveown $typtopexec
chmod $savemod $typtopexec

touch /var/log/typtop.log && chmod o+w /var/log/typtop.log


# ------- OS Specific differences -----
for f in ${authorized_execs[@]}; do
    f=/usr/bin/$f
    if [ -e $f ]; then
        shasum -a 256 $f > ${db_root}/authorized_caller;
    fi
done

for f in ${authorized_execs[@]} ; do
    f=/etc/pam.d/$f
    if [ ! -e $f ]; then continue ; fi ;
    if [ "$(grep pam_opendirectory_typo $f)" != "" ]; then
	    echo "Already instaled ignoring...";
    else
	    sed -i '.bak' 's/^auth\(.*\)pam_opendirectory.so/auth\1\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/g' $f ;
    fi ;
done
