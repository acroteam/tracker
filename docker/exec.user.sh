#!/bin/bash -xu

SCRIPT_BASENAME="$(basename "${0}" .sh)"
DOCKER_IMAGE="${SCRIPT_BASENAME#exec.user.}"

container_name() {
  echo "$@" | tr ':' '_'
}

CONTAINER_ID="`container_name ${DOCKER_IMAGE}`"

docker exec -it -u `id -u`:`id -g` -w `realpath .` "${CONTAINER_ID}" bash
