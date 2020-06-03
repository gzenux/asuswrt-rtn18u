#!/usr/bin/env bash

[[ "$0" = "$BASH_SOURCE" ]] && {
	echo "Error: This script needs to be sourced. Please run as '. $BASH_SOURCE'"
	exit 1
}

PrjDir=$(dirname $(dirname $(readlink -e $BASH_SOURCE)))
SrcDir=${PrjDir}/release/src-rt-6.x.4708
TOOLCHAIN="${SrcDir}/toolchains/hndtools-arm-linux-2.6.36-uclibc-4.5.3"

# add the toolchain into PATH
echo $PATH | grep ${TOOLCHAIN}/bin > /dev/null 2>&1 || export PATH="$PATH:${TOOLCHAIN}/bin"

# CFE build configuration (Optional)
echo $PATH | grep ${SrcDir}/ctools > /dev/null 2>&1 || {
	export PATH="$PATH:${SrcDir}/ctools"
	export LD_LIBRARY_PATH="${TOOLCHAIN}/lib"
}

cd ${SrcDir} > /dev/null

# unset variables only used in this script
unset PrjDir SrcDir TOOLCHAIN
