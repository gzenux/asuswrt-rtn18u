#!/usr/bin/env bash
set -Eeuo pipefail

ImageName=asuswrt
ImageTag=latest
HostName=${ImageName}
WorkDir="/work/${ImageName}"
DockerfileDir=$(readlink -f "$(dirname $BASH_SOURCE)")

function usage() {
	cat <<EOF >&2
Usage: $(basename $BASH_SOURCE) [options] [-- <command>]

Options:
   -d|--detach
      start a container in detached mode
      default: $Detach
   -u|--update
      update/rebuild the docker image before run this image
      default: $Update
   -f|--force
      force rebuild the docker image without docker cache
      default: $Force
   -t|--tag
      change image tag to build/run the docker image
      default: $ImageTag
   -r|--release
      run the docker image with a fake username 'builder' is used to build the release firmware
   -h|--help
      show this usage

EOF
}

# options
Detach=false
Update=false
Force=false
ReleaseUser=${USER}
ReleaseHome=${HOME}
Help=false
Opts=$(getopt -o dufrt:h --long detach,update,force,release,tag:,help -- "$@")
[[ $? != 0 ]] && { usage; exit 1; }
eval set -- "$Opts"
while true; do
	case "$1" in
		-d|--detach) Detach=true; shift;;
		-u|--update) Update=true; shift;;
		-f|--force)  Update=true; Force=true; shift;;
		-t|--tag)    ImageTag=$2; shift 2;;
		-r|--release) ReleaseUser=builder; ReleaseHome=/${ReleaseUser}; shift 1;;
		-h|--help)   Help=true; shift;;
		--)          shift; break;;
		*) echo "Arguments parsing error"; exit 1;;
	esac
done

[[ "$Help" == true ]] && { usage; exit 0; }

Image=${ImageName}:${ImageTag}
[[ "$(docker images -q ${Image})" == "" || "$Update" == true ]] && {
	[[ "$Force" == true ]] && BuildOpts="--no-cache" || BuildOpts=""
	docker build ${BuildOpts} -t ${Image} ${DockerfileDir}
}

# prepare mount directories
MountDirOpts="-v $PWD:$WorkDir"

# prepare docker run options
[[ "$Detach" == true ]] && RunOpts="--rm -d" || RunOpts="--rm -it"
RunOpts="${RunOpts} --hostname ${HostName}"
RunOpts="${RunOpts} --workdir ${WorkDir}"
RunOpts="${RunOpts} --env UID=${UID} --env USER=${ReleaseUser} --env HOME=${ReleaseHome}"

# run docker container
docker run ${RunOpts} ${MountDirOpts} ${Image} $@
