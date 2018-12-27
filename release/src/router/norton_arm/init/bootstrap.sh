#!/bin/sh
#
# Copyright (c) 2012 Symantec Corporation. All rights reserved.
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

# Go up two folders to get the NGA working dir
NGADIR="$( cd "$SCRIPTDIR/.." && pwd )"

# Layout details
EXEC="$NGADIR/bin/bootstrap"
PIDFILE="/var/run/bootstrap.pid"
OPTIONS="-d $NGADIR"
LIB="$NGADIR/lib"
PROG="NGA Bootstrap"

nga_enabled() {
    if [ "$SRC" != "rc" ]; then
        # Not controlled by "rc". Assume enabled.
        return 1
    fi

    # Otherwise, check nga_enable environment variable.
    NGA_ENABLED=`/usr/sbin/nvram get nga_enable`

    if [ "$NGA_ENABLED" = "" ] || [ "$NGA_ENABLED" = 0 ]; then
        return 0        # Disabled
    else
        return 1        # Enabled
    fi
}

success() {
    echo -n "success"
    return
}

failure() {
    echo -n "failed"
    return
}

getpid() {
    if [ -f "$PIDFILE" ]; then
        PID=`cat $PIDFILE`
    else
        PID=0
    fi
}

rccheck() {
    if [ "$SRC" = "rc" ]; then
        echo "Restarting $PROG: Nothing to do from rc"
        return 1
    fi
    return 0
}

start() {
    nga_enabled
    if [ $? -ne 1 ]; then 
        echo "Norton Home is disabled"
        return 0
    fi

    echo -n "Starting $PROG: "
    getpid
    if [ $PID -ne 0 ]; then
        echo "already running (pid=$PID)"
        reload
    else
        export LD_LIBRARY_PATH=$LIB:$LD_LIBRARY_PATH
        $EXEC $OPTIONS
        RETVAL=$?
        [ $RETVAL -eq 0 ] && success || failure
    fi;
    echo
    return $RETVAL
}

stop() {
    rccheck
    if [ $? -eq 1 ]; then 
        nga_enabled
        if [ $? -eq 1 ]; then
            return 0
        else
            echo "$PROG was disabled..."
        fi
    fi

    echo -n "Stopping $PROG: "
    getpid
    if [ $PID -ne 0 ]; then
        kill -TERM $PID
        RETVAL=$?
        while [ -f "$PIDFILE" ]; do sleep 1; done
        [ $RETVAL -eq 0 ] && success || failure
    else
        RETVAL=0
        echo -n "not running"
    fi;
    echo
    return $RETVAL
}

restart() {
    stop
    start
}

reload() {
    echo -n "Reloading $PROG config: "
    getpid
    if [ $PID -ne 0 ]; then
        kill -HUP $PID
        RETVAL=$?
        [ $RETVAL -eq 0 ] && success || failure
    else
        echo -n "not running"
    fi;
    echo
    return $RETVAL
}

# Determine the source of this request
if [ $# -eq 2 ]; then
    SRC=$2
else
    SRC="manual"
fi

# Process the input param
case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    restart
    ;;
  reload)
    reload
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|reload} [src]"
    RETVAL=1
esac

exit $RETVAL
