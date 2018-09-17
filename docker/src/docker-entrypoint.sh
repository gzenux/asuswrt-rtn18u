#!/usr/bin/env bash
set -Eeuo pipefail

[[ $UID == 0 ]] && {
	exec "$@"
} || {
	# Add user and switch to the user
	{
		mkdir -p $(dirname $HOME)
		useradd -m -u $UID -d $HOME $USER
		passwd -d $USER
		gpasswd -a $USER sudo
		sed -i 's:%sudo\tALL=(ALL\:ALL) ALL:%sudo\tALL=NOPASSWD\: ALL:g' /etc/sudoers
	} &> /dev/null
	exec sudo -su $USER exec "$@"
}
