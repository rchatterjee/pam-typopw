#!/bin/bash
set -e
if [ "$(id -u)" != "0" ]; then 
    echo "You need root priviledge to run this script."
    exit;
fi

# Compile chkpw and set chkpw permissions
gcc chkpw.c -o chkpw -lcrypt
chown root:shadow ./chkpw
chmod g+s ./chkpw



# install libpam_python, and python-dawg
apt-get install libpam-python libdawgdic-dev

# instal dawg, pwmodel and mistypogrpahy (REMOVING THESE DEPENDENCIES)
# pip install --upgrade dawg
# pip install --upgrade git+https://github.com/rchatterjee/pwmodels.git
# pip install --upgrade git+https://github.com/rchatterjee/mistypography.git


# Test whether the installation was correct or not
python -c "import typofixer.checker" 
if [ "$?" != "0" ]; 
then
    echo "You have to install pwmodels, and mistypogrpahy modules by hand. "
    echo "Please see the installation instruction in https://github.com/rchatterjee/mistypogrpahy.git."
    echo "Inconvenience is deeply regretted. If you want to send a feedback please direct it to rahul@cs.cornell.edu"
else
    echo "The python pam module seems to be all install correctly."
fi


# Finally connect the pam-module with the dummy app 'test' 
echo "auth   sufficient   pam_python.so $(pwd)/pam_typotolerant.py" > /etc/pam.d/test

# Now, you are on your own
echo "******************************************************"
echo "Seems like everything is done. Now you can test using"
echo "$ python test_pam.py"
echo "You can check the errors in /var/log/auth.log file"
echo "******************************************************"
