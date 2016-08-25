#!/bin/bash
if [ "$(id -u)" != "0" ]; then 
    echo "You need root priviledge to run this script."
    exit;
fi

# remove pip libraries
pip uninstall dawg pwmodels typofixer

# remove dawg
sudo apt-get remove libpam-python libdawgdic-dev

# rm -rf /etc/pam.d/test
