#!/bin/bash
# https://xkcd.com/1654/
set -e
set -u
set -x

curdir="$(dirname "$0")"
platform=$(uname)
if [[ "$platform" == "Linux" ]]; then
    subdir='linux/'
    makecmd='make && make install'
    sudo apt-get install libssl-dev libpam-dev
elif [[ "$platform" == "Darwin" ]]; then
    subdir='osx/prebuilt/'
    makecmd='./install.sh'
fi

cd $curdir/$subdir
pwd
$makecmd
cd -
