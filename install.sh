#!/bin/bash
set -e
if [ "$(id -u)" != "0" ]; then 
    echo "You need root priviledge to run this script."
    exit;
fi

# Compile chkpw and set chkpw permissions
gcc chkpw.c -o chkpw -lcrypt
unix_chkpwd=$(which unix_chkpwd)

if [[ ! -z "$unix_chkpwd" ]];
then
    sudo chown --reference=${unix_chkpwd} chkpw
    sudo chmod --reference=${unix_chkpwd} chkpw
else
    chown root:shadow ./chkpw
    chmod g+s ./chkpw
fi

bindir=/usr/local/bin/
libdir=/usr/local/lib
if [ ! -e $bindir ]; then
    mkdir -p $bindir
fi
if [ ! -e $libdir ]; then
    mkdir -p $libdir
fi

# Installs the pam_typotolerant script and required libraries.
python setup.py install --install-scripts=$bindir --install_lib=$libdir

# cp pam_typotolerant.py chkpw ${bindir}

# install libpam_python, and python-dawg
apt-get install libpam-python python-pam

# libpam-python is for writing pam modules in python
# libdawgdic-dev is for dawg functionalities, used for NOTHING!! TODO: remove
# python-pam calling pam functions via python, used for testing. 

# Finally create a pam-file and update common-auth
common_auth_file=/etc/pam.d/common-auth
echo "auth   sufficient   pam_python.so ${bindir}/pam_typotolerant.py" > /etc/pam.d/typo_auth

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
