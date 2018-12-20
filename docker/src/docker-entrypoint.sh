#!/usr/bin/env bash
set -Eeuo pipefail

[[ $UID == 0 ]] && {
	OptUSER=""
} || {
	# Add user and switch to the user
	{
		mkdir -p $(dirname $HOME)
		useradd -m -s /bin/bash -u $UID -d $HOME $USER
		passwd -d $USER
		chown $USER $(tty)
		gpasswd -a $USER sudo
		sed -i 's:%sudo\tALL=(ALL\:ALL) ALL:%sudo\tALL=NOPASSWD\: ALL:g' /etc/sudoers
	} &> /dev/null
	OptUSER="-u $USER"
}
sudo -Es ${OptUSER} exec "$@"
