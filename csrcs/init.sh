#!/bin/bash

set -e 
set -u
set -x

curdir="$(dirname "$0")"
platform=$(uname)
if [[ "$platform" == "Linux" ]]; then
    subdir='linux/'
    makecmd='make'
elif [[ "$platform" == "Darwin" ]]; then
    subdir='osx/pam_opendirectory/'
    makecmd='make all'
fi

cd $curdir/$subdir
pwd
${makecmd} && make install

cd -
