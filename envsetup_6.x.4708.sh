#!/usr/bin/env bash

if [ -n "$BASH_SOURCE" ]; then
	THIS_SCRIPT=$BASH_SOURCE
elif [ -n "$ZSH_NAME" ]; then
	THIS_SCRIPT=$0
else
	THIS_SCRIPT="$(pwd)/envsetup_6.x.4708.sh"
fi

if [ -z "$ZSH_NAME" ] && [ "$0" = "$THIS_SCRIPT" ]; then
	echo "Error: This script needs to be sourced. Please run as '. $THIS_SCRIPT'"
	exit 1
fi

PrjDir=$(dirname "$(readlink -f $THIS_SCRIPT)")
SrcDir=${PrjDir}/release/src-rt-6.x.4708
TOOLCHAIN="${SrcDir}/toolchains/hndtools-arm-linux-2.6.36-uclibc-4.5.3"

# add the toolchain into PATH
echo $PATH | grep ${TOOLCHAIN}/bin > /dev/null 2>&1 || export PATH="$PATH:${TOOLCHAIN}/bin"

# CFE build configuration (Optional)
echo $PATH | grep ${SrcDir}/ctools > /dev/null 2>&1 || export PATH="$PATH:${SrcDir}/ctools"
echo $LD_LIBRARY_PATH | grep ${TOOLCHAIN}/lib > /dev/null 2>&1 || export LD_LIBRARY_PATH="${TOOLCHAIN}/lib"

cd ${SrcDir} > /dev/null

# unset variables only used in this script
unset PrjDir SrcDir TOOLCHAIN
