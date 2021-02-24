#!/bin/bash -x

TAG="$(basename "$1" .Dockerfile)"

docker build -t ${TAG} - < ${TAG}.Dockerfile
