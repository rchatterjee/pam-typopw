#!/bin/bash
set -e
if [ "$(id -u)" != "0" ]; then 
    echo "You need root priviledge to run this script."
    exit;
fi

# libpam-python is for writing pam modules in python
# libdawgdic-dev is for dawg functionalities, used for NOTHING!! TODO: remove
# python-pam calling pam functions via python, used for testing. 

# install libpam_python, and python-dawg, python-dev setuptools
apt-get install libpam-python python-pam python-setuptools python-dev python-pip
pip install numpy

# Compile chkpw and set chkpw permissions
gcc chkpw.c -o chkpw -lcrypt

bindir=/usr/local/bin/
if [ ! -e $bindir ]; then
    mkdir -p $bindir
fi

# Installs the pam_typotolerant script and required libraries.
python setup.py install \
       --install-scripts=$bindir \
       --record ffile.txt
       # --install-lib=$libdir \

cp -v -f pam_typotolerant.py chkpw $bindir/
unix_chkpwd=$(which unix_chkpwd)
chkpw=$bindir/chkpw
if [[ ! -z "$unix_chkpwd" ]];
then
    chown --reference=${unix_chkpwd} $chkpw
    chmod --reference=${unix_chkpwd} $chkpw
else
    chown root:shadow $chkpw
    chmod g+s $chkpw
fi

# Finally create a pam-file and update common-auth
common_auth_file=/etc/pam.d/common-auth
echo "auth   sufficient   pam_python.so ${bindir}/pam_typotolerant.py" > /etc/pam.d/typo_auth

if [ -e ${common_auth_file}.orig ]
then
    echo "Looks like you have an old installation of typo_auth. Removing it."
    mv ${common_auth_file}.orig ${common_auth_file}
fi
mv $common_auth_file ${common_auth_file}.orig # save for uninstall script

# Install typo tolerance
echo '@include typo_auth' > ${common_auth_file}
cat ${common_auth_file}.orig >> ${common_auth_file}


# Now, you are on your own
echo "******************************************************"
echo "Seems like everything is done. Now you can test using"
echo "$ python test_pam.py"
echo "You can check the errors in /var/log/auth.log file"
echo "******************************************************"
