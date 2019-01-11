#!/usr/bin/env bash
set -Eeuo pipefail

PrjDir=$(dirname $(dirname $(readlink -e $BASH_SOURCE)))
. ${PrjDir}/scripts/envsetup_bcm4708.sh

make rt-n18u
