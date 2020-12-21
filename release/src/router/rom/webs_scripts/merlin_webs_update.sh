#!/bin/sh

wget_options="-q -t 2 -T 30"

fwsite="https://gzenux.github.io/asuswrt-rtn18u"

# INITIALIZING
nvram set webs_state_update=0 # 0: webs_state update is in progress  1: webs_state update done
nvram set webs_state_flag=0   # 0: Don't do upgrade  1: New firmeware available  2: Do Force Upgrade
nvram set webs_state_error=0  # 1: wget fail  2: Not enough memory space  3: FW check/RSA check fail
nvram set webs_state_url=""
nvram set webs_state_info=""
nvram set webs_state_info_am=""
nvram set webs_state_info_beta=""
webs_state_flag=0
webs_state_error=0
webs_state_info=""
webs_state_info_am=""
webs_state_info_beta=""

# current firmware information
current_firm=$(nvram get buildno | cut -d. -f1)
current_buildno=$(nvram get buildno | cut -d. -f2)
current_extendno=$(nvram get extendno)

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
manifest=/tmp/wlan_update.txt
if [ "$fwup_tc" != "" ]; then
	tcase_manifest="${model}${tcase_stable}${tcase_beta}"
	echo "---- update test, case #$fwup_tc, wlan_update.txt=\"${tcase_manifest}\" ----" > $log_file
	echo "$tcase_manifest" > $manifest
else
	echo "---- update real normal ----" > $log_file
	/usr/sbin/wget $wget_options $fwsite/manifest.txt -O $manifest
fi

if [ "$?" != "0" ]; then
	nvram set webs_state_error=1
	nvram set webs_state_update=1
	exit
else
	# parse stable release information
	fullver=$(grep -m1 $model $manifest | sed s/.*#FW//;)
	fullver=$(echo $fullver | sed s/#.*//;)
	if [ "$fullver" == "" ] || [ "$fullver" == "$productid" ]; then
		# no stable release available
		webs_state_info=""
		webs_state_info_am=""
	else
		firmver=$(echo $fullver | cut -d. -f1)
		buildno=$(echo $fullver | cut -d. -f2)
		extendno=$(grep -m1 $model $manifest | sed s/.*#EXT//;)
		extendno=$(echo $extendno | sed s/#.*//;)
		lextendno=$(echo $extendno | sed s/-g.*//;)
		lextendno=$(echo $lextendno | sed "s/^[0-9]$/10&/;")
		webs_state_info=3004_${firmver}_${buildno}_${extendno}
		webs_state_info_am=${firmver}_${buildno}_${extendno}
	fi

	# parse beta release information
	fullver_beta=$(grep -m1 $model $manifest | sed s/.*#BETAFW//;)
	fullver_beta=$(echo $fullver_beta | sed s/#.*//;)
	if [ "$fullver_beta" == "" ] || [ "$fullver_beta" == "$productid" ] || [ "$firmware_path" != "1" ]; then
		# no beta release available or skip beta release checking
		webs_state_info_beta=""
	else
		firmver_beta=$(echo $fullver_beta | cut -d. -f1)
		buildno_beta=$(echo $fullver_beta | cut -d. -f2)
		extendno_beta=$(grep -m1 $model $manifest | sed s/.*#BETAEXT//;)
		extendno_beta=$(echo $extendno_beta | sed s/#.*//;)
		lextendno_beta=$(echo $extendno_beta | sed s/-g.*//;)
		lextendno_beta=$(echo $lextendno_beta | sed s/^alpha/1/;)
		lextendno_beta=$(echo $lextendno_beta | sed s/^beta/5/;)
		webs_state_info_beta=${firmver_beta}_${buildno_beta}_${extendno_beta}
	fi

	rm -f /tmp/wlan_update.*
fi

echo "---- Have ${current_firm}.${current_buildno}_${current_extendno} ----" >> $log_file
if [ "$webs_state_info_am" == "" ] && [ "$webs_state_info_beta" == "" ]; then
	echo "---- No any firmware update available! ----" >> $log_file
	nvram set webs_state_update=1
	exit
else
	if [ "$webs_state_info_am" != "" ]; then
		echo "---- Stable available ${firmver}.${buildno}_${extendno} ----" >> $log_file
	else
		echo "---- No stable release available ----" >> $log_file
	fi
	if [ "$webs_state_info_beta" != "" ]; then
		echo "---- Beta available ${firmver_beta}.${buildno_beta}_${extendno_beta} ----" >> $log_file
	else
		if [ "$firmware_path" == "1" ]; then
			echo "---- No beta release available ----" >> $log_file
		else
			echo "---- Skip ckeck beta release ----" >> $log_file
		fi
	fi
fi

# download stable release note
get_release_note=0
if [ "$webs_state_info_am" != "" ] && [ "$firmver" != "" ] && [ "$buildno" != "" ] && [ "$lextendno" != "" ]; then
	if [ "$current_firm" -lt "$firmver" ]; then
		echo "---- firmver: $firmver ----" >> $log_file
		get_release_note=1
	elif [ "$current_firm" -eq "$firmver" ]; then
		if [ "$current_buildno" -lt "$buildno" ]; then
				echo "---- buildno: $buildno ----" >> $log_file
				get_release_note=1
		elif [ "$current_buildno" -eq "$buildno" ]; then
			if [ "$current_extendno" -lt "$lextendno" ]; then
				echo "---- lextendno: $lextendno ----" >> $log_file
				get_release_note=1
			fi
		fi
	fi
fi

if [ "$get_release_note" == "1" ]; then
	releasenote_file0=${webs_state_info_am}_note.txt
	releasenote_path0="/tmp/release_note0.txt"
	if [ "$fwup_tc" != "" ]; then
		echo "---- [test] download stable release note from $fwsite/$releasenote_file0 ----" >> $log_file
		echo "${firmver}_${buildno}_${extendno} release note" > $releasenote_path0
	else
		echo "---- download stable release note from $fwsite/$releasenote_file0 ----" >> $log_file
		/usr/sbin/wget $wget_options $fwsite/$releasenote_file0 -O $releasenote_path0
	fi
	if [ "$?" != "0" ]; then
		webs_state_error=1
		webs_state_info=""
		webs_state_info_am=""
		echo "---- download stable release note failed ----" >> $log_file
	fi
else
	webs_state_info=""
	webs_state_info_am=""
	echo "---- Skip download stable release note ----" >> $log_file
fi

# download beta release note
get_release_note=0
if [ "$webs_state_info_beta" != "" ] && [ "$firmver_beta" != "" ] && [ "$buildno_beta" != "" ] && [ "$lextendno_beta" != "" ]; then
	if [ "$current_firm" -lt "$firmver_beta" ]; then
		get_release_note=1
	elif [ "$current_firm" -eq "$firmver_beta" ]; then
		if [ "$current_buildno" -lt "$buildno_beta" ]; then
			get_release_note=1
		elif [ "$current_buildno" -eq "$buildno_beta" ]; then
			if [ "$current_extendno" -lt "$lextendno_beta" ]; then
				get_release_note=1
			fi
		fi
	fi
fi

# download beta release note
if [ "$get_release_note" == "1" ]; then
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
		webs_state_error=1
		webs_state_info_beta=""
		echo "---- download beta release note failed ----" >> $log_file
	fi
else
	webs_state_info_beta=""
	echo "---- Skip download beta release note ----" >> $log_file
fi

if [ "$webs_state_info_am" == "" ] && [ "$webs_state_info_beta" == "" ]; then
	webs_state_flag=0	# Don't do upgrade
else
	webs_state_flag=1	# New firmeware available
	webs_state_error=0
fi

echo "---- Result summary:" >> $log_file
echo "---- firmware_path        = $firmware_path" >> $log_file
echo "---- webs_state_flag      = $webs_state_flag" >> $log_file
echo "---- webs_state_error     = $webs_state_error" >> $log_file
echo "---- webs_state_info      = $webs_state_info" >> $log_file
echo "---- webs_state_info_am   = $webs_state_info_am" >> $log_file
echo "---- webs_state_info_beta = $webs_state_info_beta" >> $log_file

# set nvram back
nvram set webs_state_flag="$webs_state_flag"
nvram set webs_state_error="$webs_state_error"
nvram set webs_state_info="$webs_state_info"
nvram set webs_state_info_am="$webs_state_info_am"
nvram set webs_state_info_beta="$webs_state_info_beta"
nvram set webs_state_update=1
