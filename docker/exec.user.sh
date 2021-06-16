#!/bin/bash -xu

SCRIPT_BASENAME="$(basename "${0}" .sh)"
DOCKER_IMAGE="${SCRIPT_BASENAME#exec.user.}"

container_name() {
  echo "$@" | tr ':' '_'
}

CONTAINER_ID="`container_name ${DOCKER_IMAGE}`"

docker_exec() {
  docker exec -it \
    -u `id -u`:`id -g` \
    -w `realpath .` \
    "${CONTAINER_ID}" \
    "$@"
}

# 'bash' is good default in case no command was specified
if [[ "$#" -lt 1 ]] ; then
  echo >&2 "Usage: $0 command"
  docker_exec "bash"
  #exit 1
else
  docker_exec "$@"
fi
