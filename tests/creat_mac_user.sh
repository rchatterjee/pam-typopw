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

# A list of (secondary) groups the user should belong to
# This makes the difference between admin and non-admin users.
# Leave only one uncommented
SECONDARY_GROUPS=""  # for a non-admin user
# SECONDARY_GROUPS="admin _lpadmin _appserveradm _appserverusr" # for an admin user

# ====

if [[ $UID -ne 0 ]]; then echo "Please run $0 as root." && exit 1; fi
dscl . -list /Users/$USERNAME
if [[ "$?" == "0" ]]; then
    dscl . -delete /Users/$USERNAME
    rm -rf /Users/$USERNAME
fi

# Find out the next available user ID
MAXID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -ug | tail -1)
USERID=$((MAXID+1))

# Create the user account
dscl . -create /Users/$USERNAME
dscl . -create /Users/$USERNAME UserShell /bin/bash
dscl . -create /Users/$USERNAME RealName "$FULLNAME"
dscl . -create /Users/$USERNAME UniqueID "$USERID"
dscl . -create /Users/$USERNAME PrimaryGroupID 20
dscl . -create /Users/$USERNAME NFSHomeDirectory /Users/$USERNAME

dscl . -passwd /Users/$USERNAME $PASSWORD


# # Add use to any specified groups
# for GROUP in $SECONDARY_GROUPS ; do
#     dseditgroup -o edit -t user -a $USERNAME $GROUP
# done

# Create the home directory
# createhomedir -c > /dev/null

echo "Created user #$USERID: $USERNAME ($FULLNAME)"
