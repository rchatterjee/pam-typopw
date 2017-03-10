#!/bin/bash


if [ $# -le 1 ];
then
    echo "Creates a user account the the given username and password."
    echo "Usage: $0 <username> <password>"
    exit
fi

USERNAME="$1"
FULLNAME="tmp tmp"
PASSWORD="$2"

if [[ $UID -ne 0 ]]; then echo "Please run $0 as root." && exit 1; fi

cut -d : -f 1 /etc/group | grep -w $USERNAME
if [[ "$?" == "0" ]]; then
    sudo userdel $USERNAME
fi

useradd -u 2540 -p "$PASSWORD" "$USERNAME"

if [[ "$?" == "0" ]]; then
    echo "Successfully cretaed $USERNAME"
fi
