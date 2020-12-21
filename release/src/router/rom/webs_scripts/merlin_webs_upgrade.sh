#!/bin/sh

wget_options="-t 2 -T 30"

fwsite="https://gzenux.github.io/asuswrt-rtn18u"

nvram set webs_state_upgrade=0 # INITIALIZING
nvram set webs_state_error=0

log_file=/tmp/webs_upgrade.log
echo "---- webs_upgrade start ----" > $log_file

# fwupdate test case
# test case number
fwup_tc=$(nvram get fwup_tc)

# get user update option, 1: stable + beta, 0|others: stable only
firmware_path=$(nvram get firmware_path)

# determine the firmware source (i.e stable or beta release channel)
get_beta_release=0
webs_state_info=$(nvram get webs_state_info_am)
webs_state_info_beta=$(nvram get webs_state_info_beta)
if [ "$firmware_path" == "1" ] && [ "$webs_state_info_beta" != "" ]; then
	if [ "$webs_state_info" != "" ]; then
		# need to compare which firmware is newer
		firmver=$(echo $webs_state_info | cut -d_ -f1)
		buildno=$(echo $webs_state_info | cut -d_ -f2)
		extendno=$(echo $webs_state_info | cut -d_ -f3)
		lextendno=$(echo $extendno | sed s/-g.*//;)
		lextendno=$(echo $lextendno | sed "s/^[0-9]$/10&/;")
		firmver_beta=$(echo $webs_state_info_beta | cut -d_ -f1)
		buildno_beta=$(echo $webs_state_info_beta | cut -d_ -f2)
		extendno_beta=$(echo $webs_state_info_beta | cut -d_ -f3)
		lextendno_beta=$(echo $extendno_beta | sed s/-g.*//;)
		lextendno_beta=$(echo $lextendno_beta | sed s/^alpha/1/;)
		lextendno_beta=$(echo $lextendno_beta | sed s/^beta/5/;)

		echo "---- Compare $webs_state_info and $webs_state_info_beta ----" >> $log_file
		if [ "$firmver" -lt "$firmver_beta" ]; then
			get_beta_release=1
			echo "---- firmver = $firmver < firmver_beta = $firmver_beta ----" >> $log_file
		elif [ "$firmver" -eq "$firmver_beta" ]; then
			if [ "$buildno" -lt "$buildno_beta" ]; then
				get_beta_release=1
				echo "---- buildno = $buildno < buildno_beta = $buildno_beta ----" >> $log_file
			elif [ "$buildno" -eq "$buildno_beta" ]; then
				if [ "$lextendno" -lt "$lextendno_beta" ]; then
					get_beta_release=1
					echo "---- lextendno = $lextendno < lextendno_beta = $lextendno_beta ----" >> $log_file
				else
					echo "---- lextendno = $lextendno > lextendno_beta = $lextendno_beta ----" >> $log_file
				fi
			else
				echo "---- buildno = $buildno > buildno_beta = $buildno_beta ----" >> $log_file
			fi
		else
			echo "---- firmver = $firmver > firmver_beta = $firmver_beta ----" >> $log_file
		fi
	else
		# get beta firmware
		get_beta_release=1
	fi
fi

# prepare firmware url information
model=$(nvram get productid)
if [ "$get_beta_release" == "1" ]; then
	fullver="$webs_state_info_beta"
	if [ "$(echo $fullver | grep alpha)" != "" ]; then
		relpath=alpha
	else
		relpath=${model}/beta
	fi
else
	relpath=${model}
	fullver="$webs_state_info"
fi
echo "---- fullver = $fullver ----" >> $log_file
firmver=$(echo $fullver | cut -d_ -f1)
buildno=$(echo $fullver | cut -d_ -f2)
extendno=$(echo $fullver | cut -d_ -f3)
firmware_file=${model}_${firmver}.${buildno}_${extendno}.trx

# reset firmware_path to store downloaded firmware
firmware_path="/tmp/linux.trx"

# get firmware trx file
echo 3 > /proc/sys/vm/drop_caches
if [ "$fwup_tc" != "" ]; then
	echo "---- wget fw test, url = ${fwsite}/${relpath}/${firmware_file} ----" >> $log_file
	percent=0; echo "" > /tmp/fwget_log
	while [ $percent -lt 101 ];do echo "${percent}% " >> /tmp/fwget_log; percent=$((percent+=4)); sleep 1; done
	echo "---- wget fw test done ----" >> $log_file
	# always download failure in test mode
	nvram set webs_state_error=1
	nvram set webs_state_upgrade=1
	rm /tmp/fwget_log
	exit
else
	echo "---- wget fw Real, url = ${fwsite}/${relpath}/${firmware_file} ----" >> $log_file
	wget $wget_options --output-file=/tmp/fwget_log ${fwsite}/${relpath}/${firmware_file} -O $firmware_path
fi

if [ "$?" != "0" ]; then	#download failure
	nvram set webs_state_error=1
else
	nvram set webs_state_upgrade=2
	echo "---- mv trx OK ----" >> $log_file
	nvram set firmware_check=0
	firmware_check $firmware_path
	sleep 1
	if [ "$(nvram get firmware_check)" == "1" ]; then
		echo "---- fw check OK ----" >> $log_file
		/sbin/ejusb -1 0
		rc rc_service restart_upgrade
	else
		echo "---- fw check error ----" >> $log_file
		nvram set webs_state_error=3	# wrong fw
	fi
fi

nvram set webs_state_upgrade=1
