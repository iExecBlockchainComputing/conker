#!/bin/bash
set -o errexit
set -x
BASE_NAME=conker-example-app
releasedir=./.release
distdir=${releasedir}/dist
GOPROXY=https://goproxy.cn,direct
BASEDIR="$( cd "$( dirname "$0"  )" && pwd  )"
VERSION=
buildTime=$(date +%F-%H)
git_commit=
DOCKER_PATH=./hack/docker

if [ -z "$VERSION" ];then
    VERSION=latest
fi
release_desc=${VERSION}-${git_commit}-${buildTime}
function build::image() {
   PROXY=$1
   PUSHTOHUB=$2
   HUB_ADDR=$3
   HUB_REP=$4
   HUB_USER_NAME=$5
   HUB_PASSWD=$6
	echo "---> Build Image"
	DOCKER_PATH=./hack/docker
    cd $BASEDIR/../
	HOME=`pwd`
    rm -rf $BASEDIR/../../docker-release
    cp -a $BASEDIR/../hack/docker $BASEDIR/../../docker-release
    cd $BASEDIR/../../docker-release
	cp -r $BASEDIR/../conf .
	cp -r /usr/share/zoneinfo .

	mkdir tmp
    cp -a $BASEDIR/../* tmp
	docker build --build-arg https_proxy=$PROXY --build-arg http_proxy=$PROXY --build-arg VERSION=$release_desc --no-cache -t conker-example-app:${VERSION} -f Dockerfile .
	cd $HOME
}

case $1 in
	buildimage)
		build::image $2 $3 $4 $5 $6 $7
	;;
esac