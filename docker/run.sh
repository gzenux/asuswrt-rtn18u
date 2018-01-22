#!/usr/bin/env bash

ImageName=asuswrt
ImageTag=latest
SrcName=${ImageName}
HostName=${ImageName}

function usage() {
	cat <<EOF >&2
Usage: $(basename $0) [options]

Options:
   -u|--update
      update/rebuild the docker image before run this image
      default: false
   -f|--force
      force rebuild the docker image without docker cache
      default: false
   -t|--tag
      change image tag/folder to build/run the docker image
      default: latest
   -r|--release
      run the docker image with a fake username 'builder' is used to build the release firmware
   -h|--help
      show this usage

EOF
}

# options
Update=0
Force=0
ReleaseUser=${USER}
ReleaseHome=${HOME}
Help=0
Opts=$(getopt -o ufrt:h --long update,force,release,tag:,help -- "$@")
[[ $? != 0 ]] && { usage; exit 1; }
eval set -- "$Opts"
while true; do
	case "$1" in
		-u|--update) Update=1; shift;;
		-f|--force)  Update=1; Force=1; shift;;
		-t|--tag)    ImageTag=$2; [[ -d "$(dirname $0)/${ImageTag}" ]] || { echo "$(dirname $0)/${ImageTag} does not exist!"; exit 1; }; shift 2;;
		-r|--release) ReleaseUser=builder; ReleaseHome=/${ReleaseUser}; shift 1;;
		-h|--help)   Help=1; shift;;
		--)          shift; break;;
		*) echo "Arguments parsing error"; exit 1;;
	esac
done

[[ "$Help" == 1 ]] && { usage; exit 0; }

[[ "${ReleaseUser}" != "${USER}" ]] && Image=${ImageName}:${ImageTag}.${ReleaseUser} || Image=${ImageName}:${ImageTag}
[[ "$(docker images -q ${Image})" == "" || "$Update" == 1 ]] && {
	[[ -d "$(dirname $0)/${ImageTag}" ]] && pushd $(dirname $0)/${ImageTag} || pushd $(dirname $0)
	[[ "$Force" == 1 ]] && buildopts="--no-cache"
	docker build ${buildopts} --build-arg HOME=${ReleaseHome} --build-arg USER=${ReleaseUser} --build-arg UID=${UID} -t ${Image} .
	popd
}

docker run --rm --hostname ${HostName} -v $(pwd):${ReleaseHome}/${SrcName} -it ${Image}
