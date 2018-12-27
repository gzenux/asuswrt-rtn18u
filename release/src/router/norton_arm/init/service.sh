#!/bin/sh
#
# Copyright (c) 2013 Symantec Corporation. All rights reserved.
#
# THIS SOFTWARE CONTAINS CONFIDENTIAL INFORMATION AND TRADE SECRETS OF SYMANTEC
# CORPORATION.  USE, DISCLOSURE OR REPRODUCTION IS PROHIBITED WITHOUT THE PRIOR
# EXPRESS WRITTEN PERMISSION OF SYMANTEC CORPORATION.
#
# The Licensed Software and Documentation are deemed to be commercial computer
# software as defined in FAR 12.212 and subject to restricted rights as defined in
# FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and
# DFARS 227.7202, "Rights in Commercial Computer Software or Commercial Computer
# Software Documentation", as applicable, and any successor regulations.  Any use,
# modification, reproduction release, performance, display or disclosure of the
# Licensed Software and Documentation by the U.S. Government shall be solely in
# accordance with the terms of this Agreement.
#

# Get the script name
SCRIPTNAME="$( basename "$0" )"

# Get the directory this script is running from
SCRIPTDIR="$( cd "$( dirname "$0" )" && pwd )"

COMPONENTDIR=${SCRIPTDIR}.d

CMD=${1-status}

for OneComponent in ${COMPONENTDIR}/*; do
    if [ -f $OneComponent ]; then
        echo "--- ${CMD}ing ${OneComponent} ---"
        sh $OneComponent $CMD
    fi
done
