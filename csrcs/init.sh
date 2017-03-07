#!/bin/bash
# https://xkcd.com/1654/
set -e 
set -u
set -x

curdir="$(dirname "$0")"
platform=$(uname)
if [[ "$platform" == "Linux" ]]; then
    subdir='linux/'
    makecmd='make'
    sudo apt-get install libssl-dev libpam-dev
elif [[ "$platform" == "Darwin" ]]; then
    subdir='osx/pam_opendirectory/'
    makecmd='make all'
fi

cd $curdir/$subdir
pwd
${makecmd} && make install

cd -
