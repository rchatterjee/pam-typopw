#!/bin/bash
set -e
set -u
set -x

curdir="$(dirname "$0")"
cd $curdir
echo "Installing Typtop..."
platform=$(uname)
unixchkpwd=$(which su)  # su, for darwin, unix_chkpwd for linux
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
authorized_execs=(su screensaver)

typtopexec=${script_root}/typtop

platform=$(uname)

install -m 0755 -d ${lib_root}/security/
install -m 0755 -d ${script_root}
install -m 0771 -d ${db_root}
install -m 0755 pam_opendirectory_typo.so ${lib_root}/security/
install -m 0755 uninstall.sh ${script_root}/typtop-uninstall.sh
install -m 0755 run_as_root $typtopexec # install typtopexec

savemod=$(stat -f "%p" $unixchkpwd)
saveown=$(stat -f "%Su:%Sg" $unixchkpwd)

chown $saveown $typtopexec
chmod $savemod $typtopexec

export PATH=$PATH:/usr/local/bin/
send_logs_script="${typtopexec} --send-log"
touch /var/log/typtop.log && chmod go+w /var/log/typtop.log
(crontab -l | sed -E '/send_typo_log.py|typtop/d';
 echo "00 */6 * * * ${send_logs_script} all >>/var/log/send_typo.log 2>&1") | sort - | uniq - | crontab -


# ------- OS Specific differences -----
touch ${db_root}/authorized_caller  # an empty file
chmod 644 ${db_root}/authorized_caller  # an empty file

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
cd -

echo "--"
echo "Congrats!! Looks like installation is successful. Hurray :)"
