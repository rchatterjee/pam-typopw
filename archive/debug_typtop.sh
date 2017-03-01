#!/bin/bash
set -x
set -u

users
su $USER -c "ls -altrh $(which su)"

# <enter correct password>
# if [ $? -neq 0 ]; then exit; else "echo password incorrect"; fi
typtop --status $USER

python -c "import pwd; print pwd.getpwnam('$USER')"

ls -altrh  /usr/local/etc/typtop.d/$USER/typtop.json

tail -n50 /var/log/typtop.log
