#!/bin/sh

wget_options="-q -t 2 -T 30"

fwsite="https://gzenux.github.io/asuswrt-rtn18u"

nvram set webs_state_update=0 # INITIALIZING
nvram set webs_state_flag=0   # 0: Don't do upgrade  1: New firmeware available  2: Do Force Upgrade
nvram set webs_state_error=0  # 1: wget fail  2: Not enough memory space  3: FW check/RSA check fail
nvram set webs_state_url=""
nvram set webs_state_info=""
nvram set webs_state_info_beta=""
webs_state_flag=0
webs_state_error=0
webs_state_info=""
webs_state_info_beta=""

#openssl support rsa check
IS_SUPPORT_NOTIFICATION_CENTER=$(nvram get rc_support|grep -i nt_center)
if [ "$IS_SUPPORT_NOTIFICATION_CENTER" != "" ]; then
. /tmp/nc/event.conf
fi

# current firmware information
current_firm=$(nvram get buildno | cut -d. -f1)
current_buildno=$(nvram get buildno | cut -d. -f2)
current_extendno=$(nvram get extendno)
#if echo $current_extendno | grep -q -E "(beta|alpha)"; then
#	current_firm_is_beta=1
#else
#	current_firm_is_beta=0
#fi
# Overload extendno: alpha is 11-19, beta is 51-59, release is 100-109.
current_extendno=$(echo $current_extendno | sed s/-g.*//;)
current_extendno=$(echo $current_extendno | sed "s/^[0-9]$/10&/;")
current_extendno=$(echo $current_extendno | sed s/^alpha/1/;)
current_extendno=$(echo $current_extendno | sed s/^beta/5/;)

# get user update option, 1: stable + beta, 0|others: stable only
firmware_path=$(nvram get firmware_path)

# fwupdate test case
# test case number
fwup_tc=$(nvram get fwup_tc)
if [ "$fwup_tc" != "" ]; then
tcase_base=$(nvram get buildno)
tcase_base_next="${current_firm}.$((${current_buildno}+1))"
if [ "$current_buildno" == "0" ]; then
	tcase_base_prev="$((${current_firm}-1)).${current_buildno}"
else
	tcase_base_prev="${current_firm}.$((${current_buildno}-1))"
fi
fi
case "$fwup_tc" in
1)# stable only > current
tcase_stable="FW${tcase_base}#EXT9#"
;;
2)# stable > beta > current
tcase_stable="FW${tcase_base_next}#EXT9#"
tcase_beta="BETAFW${tcase_base_next}#BETAEXTbeta9#"
;;
3)# beta > stable > current
tcase_stable="FW${tcase_base}#EXT9#"
tcase_beta="BETAFW${tcase_base_next}#BETAEXTbeta9#"
;;
4)# beta only > current
tcase_beta="BETAFW${tcase_base_next}#BETAEXTbeta9#"
;;
5)# current > stable > beta
tcase_stable="FW${tcase_base_prev}#EXT9#"
tcase_beta="BETAFW${tcase_base_prev}#BETAEXTbeta9#"
;;
*)fwup_tc="";nvram set fwup_tc="";;
esac

# get firmware information
productid=$(nvram get productid)
model="${productid}#"
log_file=/tmp/webs_update.log
if [ "$fwup_tc" != "" ]; then
	tcase_manifest="${model}${tcase_stable}${tcase_beta}"
	echo "---- update test, case #$fwup_tc, wlan_update.txt=\"${tcase_manifest}\" ----" > $log_file
	echo "$tcase_manifest" > /tmp/wlan_update.txt
else
	echo "---- update real normal ----" > $log_file
	/usr/sbin/wget $wget_options $fwsite/manifest.txt -O /tmp/wlan_update.txt
fi

if [ "$?" != "0" ]; then
	# nvram set webs_state_flag=0
	nvram set webs_state_error=1
	# nvram set webs_state_info=""
	# nvram set webs_state_info_beta=""
	nvram set webs_state_update=1
	exit
else
	# parse latest information
	fullver=$(grep -m1 $model /tmp/wlan_update.txt | sed s/.*#FW//;)
	fullver=$(echo $fullver | sed s/#.*//;)
	if [ "$fullver" == "" ] || [ "$fullver" == "$productid" ]; then
		# no latest available
		webs_state_info=""
	else
		firmver=$(echo $fullver | cut -d. -f1)
		buildno=$(echo $fullver | cut -d. -f2)
		extendno=$(grep -m1 $model /tmp/wlan_update.txt | sed s/.*#EXT//;)
		extendno=$(echo $extendno | sed s/#.*//;)
		lextendno=$(echo $extendno | sed s/-g.*//;)
		lextendno=$(echo $lextendno | sed "s/^[0-9]$/10&/;")
		webs_state_info=${firmver}_${buildno}_${extendno}
	fi

	# parse beta information
	fullver_beta=$(grep -m1 $model /tmp/wlan_update.txt | sed s/.*#BETAFW//;)
	fullver_beta=$(echo $fullver_beta | sed s/#.*//;)
	if [ "$fullver_beta" == "" ] || [ "$fullver_beta" == "$productid" ] || [ "$firmware_path" != "1" ]; then
		# no beta available or get stable only
		webs_state_info_beta=""
	else
		firmver_beta=$(echo $fullver_beta | cut -d. -f1)
		buildno_beta=$(echo $fullver_beta | cut -d. -f2)
		extendno_beta=$(grep -m1 $model /tmp/wlan_update.txt | sed s/.*#BETAEXT//;)
		extendno_beta=$(echo $extendno_beta | sed s/#.*//;)
		lextendno_beta=$(echo $extendno_beta | sed s/-g.*//;)
		lextendno_beta=$(echo $lextendno_beta | sed s/^alpha/1/;)
		lextendno_beta=$(echo $lextendno_beta | sed s/^beta/5/;)
		webs_state_info_beta=${firmver_beta}_${buildno_beta}_${extendno_beta}
	fi

	rm -f /tmp/wlan_update.*
fi

echo "---- Have ${current_firm}.${current_buildno}_${current_extendno} ----" >> $log_file
if [ "$webs_state_info" == "" ] && [ "$webs_state_info_beta" == "" ]; then
	echo "---- No any firmware update available! ----" >> $log_file
	# nvram set webs_state_flag=0
	# nvram set webs_state_error=0
	# nvram set webs_state_info=""
	# nvram set webs_state_info_beta=""
	nvram set webs_state_update=1
	exit
else
	if [ "$webs_state_info" != "" ]; then
		echo "---- Stable available ${firmver}.${buildno}_${extendno} ----" >> $log_file
	else
		echo "---- No stable release available ----" >> $log_file
	fi
	if [ "$webs_state_info_beta" != "" ]; then
		echo "---- Beta available ${firmver_beta}.${buildno_beta}_${extendno_beta}----" >> $log_file
	else
		if [ "$firmware_path" == "1" ]; then
			echo "---- No beta release available ----" >> $log_file
		else
			echo "---- Skip ckeck beta release ----" >> $log_file
		fi
	fi
fi

if [ "$webs_state_info" != "" ] && [ "$firmver" != "" ] && [ "$buildno" != "" ] && [ "$lextendno" != "" ]; then
	last_webs_state_info=$(nvram get webs_last_info)
	if [ "$current_firm" -lt "$firmver" ]; then
		echo "---- firmver: $firmver ----" >> $log_file
		webs_state_flag=1	# New firmeware available
		if [ "$IS_SUPPORT_NOTIFICATION_CENTER" != "" ]; then
			if [ "$last_webs_state_info" != "$webs_state_info" ]; then
				#if [ "$current_firm_is_beta" != 1 ]; then
					Notify_Event2NC "$SYS_FW_NWE_VERSION_AVAILABLE_EVENT" "{\"fw_ver\":\"$webs_state_info\"}"    #Send Event to Notification Center
					nvram set webs_last_info="$webs_state_info"
				#fi
			fi
		fi
	elif [ "$current_firm" -eq "$firmver" ]; then
		if [ "$current_buildno" -lt "$buildno" ]; then
				echo "---- buildno: $buildno ----" >> $log_file
				webs_state_flag=1	# New firmeware available
				if [ "$IS_SUPPORT_NOTIFICATION_CENTER" != "" ]; then
					if [ "$last_webs_state_info" != "$webs_state_info" ]; then
						#if [ "$current_firm_is_beta" != 1 ]; then
							Notify_Event2NC "$SYS_FW_NWE_VERSION_AVAILABLE_EVENT" "{\"fw_ver\":\"$webs_state_info\"}"    #Send Event to Notification Center
							nvram set webs_last_info="$webs_state_info"
						#fi
					fi
				fi
		elif [ "$current_buildno" -eq "$buildno" ]; then
			if [ "$current_extendno" -lt "$lextendno" ]; then
				echo "---- lextendno: $lextendno ----" >> $log_file
				webs_state_flag=1	# New firmeware available
				if [ "$IS_SUPPORT_NOTIFICATION_CENTER" != "" ]; then
					if [ "$last_webs_state_info" != "$webs_state_info" ]; then
						#if [ "$current_firm_is_beta" != 1 ]; then
							Notify_Event2NC "$SYS_FW_NWE_VERSION_AVAILABLE_EVENT" "{\"fw_ver\":\"$webs_state_info\"}"    #Send Event to Notification Center
							nvram set webs_last_info="$webs_state_info"
						#fi
					fi
				fi
			fi
		fi
	fi
fi

# download stable release note
if [ "$webs_state_flag" == "1" ]; then
	releasenote_file0=${webs_state_info}_note.txt
	releasenote_path0="/tmp/release_note0.txt"
	if [ "$fwup_tc" != "" ]; then
		echo "---- [test] download stable release note from $fwsite/$releasenote_file0 ----" >> $log_file
		echo "${firmver}_${buildno}_${extendno} release note" > $releasenote_path0
	else
		echo "---- download stable release note from $fwsite/$releasenote_file0 ----" >> $log_file
		/usr/sbin/wget $wget_options $fwsite/$releasenote_file0 -O $releasenote_path0
	fi
	if [ "$?" != "0" ]; then
		webs_state_info=""
		echo "---- download stable release note failed ----" >> $log_file
	fi
else
	webs_state_info=""
	echo "---- Skip download stable release note ----" >> $log_file
fi

# checking for whether downloading beta release note
get_beta_release=0
if [ "$firmware_path" == "1" ] && [ "$webs_state_info_beta" != "" ] && [ "$firmver_beta" != "" ] && [ "$buildno_beta" != "" ] && [ "$lextendno_beta" != "" ]; then
	if [ "$current_firm" -lt "$firmver_beta" ]; then
		get_beta_release=1
	elif [ "$current_firm" -eq "$firmver_beta" ]; then
		if [ "$current_buildno" -lt "$buildno_beta" ]; then
			get_beta_release=1
		elif [ "$current_buildno" -eq "$buildno_beta" ]; then
			if [ "$current_extendno" -lt "$lextendno_beta" ]; then
				get_beta_release=1
			fi
		fi
	fi
fi

# download beta release note
if [ "$get_beta_release" == "1" ]; then
	releasenote_file1=${webs_state_info_beta}_note.txt
	releasenote_path1="/tmp/release_note1.txt"
	if [ "$fwup_tc" != "" ]; then
		echo "---- [test] download beta release note from $fwsite/$releasenote_file1 ----" >> $log_file
		echo "${firmver_beta}_${buildno_beta}_${extendno_beta} release note" > $releasenote_path1
	else
		echo "---- download beta release note from $fwsite/$releasenote_file1 ----" >> $log_file
		/usr/sbin/wget $wget_options $fwsite/$releasenote_file1 -O $releasenote_path1
	fi
	if [ "$?" != "0" ]; then
		webs_state_info_beta=""
		echo "---- download beta release note failed ----" >> $log_file
	fi
else
	webs_state_info_beta=""
	echo "---- Skip download beta release note ----" >> $log_file
fi

if [ "$firmware_path" == "1" ]; then
	if [ "$webs_state_info" == "" ] && [ "$webs_state_info_beta" == "" ]; then
		if [ "$webs_state_flag" == "1" ] || [ "$get_beta_release" == "1" ]; then
			# release note download fail
			webs_state_error=1
		fi
		webs_state_flag=0
	elif [ "$webs_state_info" == "" ]; then
		if [ "$webs_state_flag" != "1" ]; then
			webs_state_flag=1	# New firmeware available
		fi
	fi
elif [ "$webs_state_info" == "" ]; then
	if [ "$webs_state_flag" == "1" ]; then
		# stable release note download fail
		webs_state_flag=0
		webs_state_error=1
	fi
fi

echo "---- Result summary:" >> $log_file
echo "---- firmware_path        = $firmware_path" >> $log_file
echo "---- webs_state_flag      = $webs_state_flag" >> $log_file
echo "---- webs_state_error     = $webs_state_error" >> $log_file
echo "---- webs_state_info      = $webs_state_info" >> $log_file
echo "---- webs_state_info_beta = $webs_state_info_beta" >> $log_file

# set nvram back
nvram set webs_state_flag="$webs_state_flag"
nvram set webs_state_error="$webs_state_error"
nvram set webs_state_info="$webs_state_info"
nvram set webs_state_info_beta="$webs_state_info_beta"
nvram set webs_state_update=1
