#!/bin/bash -xu

SCRIPT_BASENAME="$(basename "${0}" .sh)"
DOCKER_IMAGE="${SCRIPT_BASENAME#exec.root.}"

container_name() {
  echo "$@" | tr ':' '_'
}

CONTAINER_ID="`container_name ${DOCKER_IMAGE}`"

docker exec -it -u 0:0 -w `realpath .` "${CONTAINER_ID}" bash
