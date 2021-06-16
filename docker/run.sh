#!/bin/bash -u

# 'pwd' reports 'logical' path preserving symlinks if any present
#CURRENT_DIR="$(realpath .)"
CURRENT_DIR="$(pwd)"
echo "CURRENT_DIR='${CURRENT_DIR}'"

SCRIPT_BASENAME="$(basename "${0}" .sh)"
DOCKER_IMAGE="${SCRIPT_BASENAME#run.}"

container_name() {
  echo "$@" | tr ':' '_'
}

CONTAINER_ID="`container_name ${DOCKER_IMAGE}`"

# GIT_DIR is the location of the .git folder. If this isn’t specified,
# Git walks up the directory tree until it gets to ~ or /, looking for a
# .git directory at every step.
get_git_dir() {
  if [[ -n "${GIT_DIR:-}" ]] ; then
    echo "${GIT_DIR}"
    return
  fi
  # 'pwd' reports 'logical' path preserving symlinks if any present
  local DIR="${CURRENT_DIR}"
  while [[ "${DIR:-/}" != "/" ]] ; do
    if [[ -e "${DIR}/.git" ]] ; then
      echo "${DIR}"
      return
    fi
    DIR="$(dirname "${DIR}")"
  done
}

get_mount_points() {
  echo >&2 "\$@='$@'"
  local DIR
  for DIR in "$@" ; do
    DIR="$(realpath -m "${DIR}")"
    while [[ "${DIR:-/}" != "/" ]] ; do
      mountpoint -q "${DIR}" && echo "${DIR}"
      DIR="$(dirname "${DIR}")"
    done
  done
}

docker_run() {
(
  # host's 'current working directory' must be available in 'docker'
  # because it will be made 'current working directory' in 'docker'
  MOUNT+=" ${CURRENT_DIR}"

  # Sometimes we need to access directories above 'current working
  # directory'. 'git repository' top level directory often act as
  # boundary for such case.
  MOUNT+=" $(get_git_dir)"

  # User's 'home directory' holds '.bash_history' with recently used
  # commands and shall be availble in 'docker' to preserve that 'history'
  # between 'docker run' sessions
  MOUNT+=" ${HOME}"

  # Intermediate 'mount points' can be necessary to properly traverse
  # directory tree
  MOUNT_POINTS="$(get_mount_points ${MOUNT} | sort -u)"
  echo >&2 "MOUNT_POINTS='${MOUNT_POINTS:-}'"
  MOUNT+=" ${MOUNT_POINTS:-}"

  # FIXME: Some items from '${MOUNT}' list may be safely omitted if they
  # are directly accessible via some other 'parent' item

  echo >&2 "MOUNT='${MOUNT}'"
  for MOUNT_ITEM in $(realpath -m ${MOUNT} | sort -u) ; do
    MOUNT_OPTIONS+=" -v ${MOUNT_ITEM}:${MOUNT_ITEM}"
  done
  echo >&2 "MOUNT_OPTIONS='${MOUNT_OPTIONS}'"
  #return

  set -x

  docker run --rm -it \
    ${MOUNT_OPTIONS:-} \
    -w "${CURRENT_DIR}" \
    -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro \
    -u `id -u`:`id -g` \
    --name ${CONTAINER_ID} \
    ${DOCKER_IMAGE} \
    "$@"

)
}

find_Dockerfile() {
  local DIRS
  DIRS+=" ."
  DIRS+=" ${CURRENT_DIR}"
  DIRS+=" $(dirname $0)"
  local DIR
  for DIR in ${DIRS} ; do
    local DOCKERFILE="${DIR}/${DOCKER_IMAGE}.Dockerfile"
    if [[ -s "${DOCKERFILE}" ]] ; then
      echo "${DOCKERFILE}"
      return
    fi
  done
}

# make sure docker image is available
if ! docker image inspect ${DOCKER_IMAGE} 1>/dev/null 2>/dev/null ; then
  DOCKERFILE="$(find_Dockerfile)"
  echo "'${DOCKER_IMAGE}' docker image is unavailable"
  echo "execute the following command to build '${DOCKER_IMAGE}' docker image"
  echo "  docker build -t ${DOCKER_IMAGE} - < ${DOCKERFILE}"
  exit 1
fi

# 'bash' is good default in case no command was specified
if [[ "$#" -lt 1 ]] ; then
  echo >&2 "Usage: $0 command"
  docker_run "bash"
  #exit 1
else
  docker_run "$@"
fi
