#!/bin/sh

wget_timeout=$(nvram get apps_wget_timeout)
#wget_options="-nv -t 2 -T $wget_timeout --dns-timeout=120"
#wget_options="-q -t 2 -T $wget_timeout --no-check-certificate"
wget_options="-t 2 -T $wget_timeout --no-check-certificate"

fwsite=$(nvram get firmware_server)
# TODO: Do we really need to check fwsite again?
#if [ "$fwsite" == "" ]; then
#	nvram set webs_state_error=1
#	nvram set webs_state_upgrade=1
#	exit
#fi

nvram set webs_state_upgrade=0 # INITIALIZING
nvram set webs_state_error=0

# prepare firmware url information
model=$(nvram get productid)
firmware_path=$(nvram get firmware_path)
if [ "$firmware_path" = "1" ]; then
	fullver=$(nvram get webs_state_info_beta)
	if [ "$(echo $fullver | grep alpha)" != "" ]; then
		relpath=alpha
	else
		relpath=${model}/beta
	fi
else
	fullver=$(nvram get webs_state_info)
	relpath=${model}
fi
firmver=$(echo $fullver | cut -d_ -f1)
buildno=$(echo $fullver | cut -d_ -f2)
extendno=$(echo $fullver | cut -d_ -f3)
firmware_file=${model}_${firmver}.${buildno}_${extendno}.trx

# reset firmware_path to store downloaded firmware
firmware_path="/tmp/linux.trx"

# get firmware trx file
forsq=$(nvram get apps_sq)
echo 3 > /proc/sys/vm/drop_caches
if [ "$forsq" == "1" ]; then
	echo "---- wget fw sq ----" > /tmp/webs_upgrade.log
	wget $wget_options --output-file=/tmp/fwget_log ${fwsite}/test/${relpath}/${firmware_file} -O $firmware_path
else
	echo "---- wget fw Real ----" > /tmp/webs_upgrade.log
	wget $wget_options --output-file=/tmp/fwget_log ${fwsite}/${relpath}/${firmware_file} -O $firmware_path
fi

if [ "$?" != "0" ]; then	#download failure
	nvram set webs_state_error=1
else
	nvram set webs_state_upgrade=2
	echo "---- mv trx OK ----" >> /tmp/webs_upgrade.log
	nvram set firmware_check=0
	firmware_check $firmware_path
	sleep 1
	if [ "$(nvram get firmware_check)" == "1" ]; then
		echo "---- fw check OK ----" >> /tmp/webs_upgrade.log
		/sbin/ejusb -1 0
		rc rc_service restart_upgrade
	else
		echo "---- fw check error ----" >> /tmp/webs_upgrade.log
		nvram set webs_state_error=3	# wrong fw
	fi
fi

nvram set webs_state_upgrade=1
