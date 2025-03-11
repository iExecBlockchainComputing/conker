#!/bin/bash
set -o errexit
set -x
BASE_NAME=conker-ra
releasedir=./.release
BASEDIR="$( cd "$( dirname "$0"  )" && pwd  )"
VERSION=$(git tag -l --points-at HEAD)
buildTime=$(date +%F-%H)
git_commit=$(git log -n 1 --pretty --format=%h)
DOCKER_PATH=./hack/docker
DEBUG=false
if [ -z "$VERSION" ];then
    VERSION=latest
fi
release_desc=${VERSION}-${git_commit}-${buildTime}
function prepare() {
	rm -rf $releasedir
    mkdir -pv $releasedir

    cp -a $BASEDIR/../src/* $releasedir

    cp -a docker/* $releasedir
    rm -rf $BASEDIR/package
}

function build::image() {
    echo $DEBUG
    PROXY=$1
    echo "---> Build Image"
    cd $releasedir
    docker build --no-cache --build-arg https_proxy=$PROXY --build-arg http_proxy=$PROXY --build-arg VERSION=$release_desc  --build-arg DEBUG=$DEBUG -t ${BASE_NAME}:${VERSION} -f Dockerfile .
	cd $HOME
}

function docker2initrd() {
   docker rm -f initrdconvert || true
   DOCKER_IMAGE=$1
   IMAGE_NAME=`echo $DOCKER_IMAGE |awk -F ':' '{print $1}'`
   IMAGE_TAG=`echo $DOCKER_IMAGE |awk -F ':' '{print $2}'`
   git clone https://gitee.com/plasma-csv/initramfs-template
   docker run -d --name initrdconvert --entrypoint sleep $DOCKER_IMAGE 60000

   OS_TYPE=`docker exec initrdconvert  cat /etc/os-release |grep -w ID |awk -F= '{print $2}'`

   case "$OS_TYPE" in
      ubuntu)
        # install systemd for boot
        docker exec initrdconvert bash  -c "apt-get -y install --no-install-recommends systemd-sysv && ln -s /bin/systemd /init"
        # install docker 
        docker exec initrdconvert bash  -c  "bash /install_docker.sh"
        # install net-tools
        docker exec initrdconvert bash -c "apt install -y netbase net-tools ethtool udev iproute2 iputils-ping ifupdown isc-dhcp-client ifupdown vim"

        if [ x${DEBUG} == xtrue ];then
           # for debug install ssh
           docker exec initrdconvert bash  -c "apt update && apt install -y ssh && sed -i s@#PermitRootLogin\ prohibit-password@PermitRootLogin\ yes@g /etc/ssh/sshd_config"
           #change the passed
           docker exec initrdconvert bash  -c  "echo 'root:admin@123' | chpasswd"
        fi
        ;;
      centos)
        echo not support now
        return
        ;;
      alpine)
        echo not support now
        return
        ;;
    *)
        echo unknow os $OS_TYPE exit!
        return
        ;;
     esac

     mv  ./initramfs-template/rootfs initramfs
     rm -rf ./initramfs-template
     docker export initrdconvert > ./initramfs/app/$IMAGE_NAME-$IMAGE_TAG.tar
}

function package() {
    mkdir -p $BASEDIR/package/initrd-${BASE_NAME}-${VERSION}
    cd $BASEDIR/package/initrd-${BASE_NAME}-${VERSION}
   
    mkdir -p conf
    cp -a $BASEDIR/docker/app.yml conf/app.yml
    mkdir -p conf/conker/backend/conf
    cp -a $BASEDIR/../src/backend/conf/app.conf conf/conker/backend/conf

    docker2initrd ${BASE_NAME}:${VERSION}

    cp $BASEDIR/install.sh .
    sed -i "s#{{VERSION}}#$VERSION#" install.sh

    cd $BASEDIR/package
    zip -ry initrd-${BASE_NAME}-${VERSION}.zip initrd-${BASE_NAME}-${VERSION}
    cd $BASEDIR

}

case $1 in
	buildimage)
	    prepare
		build::image $2
	;;
	package)
       DEBUG=false
	   prepare
	   build::image $2
	   package
	;;
    package-debug)
       # debug mode will install ssh to allow login
       DEBUG=true
       VERSION=${VERSION}-debug
	   prepare
	   build::image $2
	   package 
	;;
    package-all)
       #build debug package and product package both
       DEBUG=false
	   prepare
	   build::image $2
	   package
       # debug mode will install ssh to allow login
       DEBUG=true
       VERSION=${VERSION}-debug
	   build::image $2
	   package 
	;;
	d2i)
	   docker2initrd $2
esac
