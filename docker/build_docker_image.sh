#!/bin/bash -eux

# docker image name/tag can be passed as argument or embedded in name of symlink to this script

if [[ "$#" -lt 1 ]] ; then

# script name format: ${PREFIX}${DOCKER_IMAGE}${SUFFIX}
# where ${DOCKER_IMAGE} is ${NAME}:${TAG}
# ${TAG} is like 'version'

SUFFIX=".sh"
PREFIX="build_docker_image."

SCRIPT_BASENAME="$(basename "${0}" ${SUFFIX})"
DOCKER_IMAGE="${SCRIPT_BASENAME#${PREFIX}}"

else

SUFFIX=".Dockerfile"
DOCKER_IMAGE="$(basename "${1}" ${SUFFIX})"

fi

#TAG="$(basename "$1" .Dockerfile)"

docker build -t ${DOCKER_IMAGE} - < ${DOCKER_IMAGE}.Dockerfile
