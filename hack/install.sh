#!/usr/bin/env bash
set -o errexit
set -x
VERSION={{VERSION}}
APP_NAME=conker-ra-${VERSION}
IMAGE_NAME=initrd-${APP_NAME}
CVM_NAME="conker-5"
INSTALL_DIR=${CVM_NAME}
CSV_BASE_DIR=/opt/cvm
QEMU_FOR_CSV_PATH=qemu-system-x86_64 
CSV_MEMORY=16G
CSV_CPUS=8
GUEST_CID=4
CSV_ENCRYPTED_DISK_SIZE1=50G
CSV_MAC=52:a4:00:12:34:85
VNC_PORT=:5

BASEDIR="$( cd "$( dirname "$0"  )" && pwd  )"
function SetConf() {
    rm -rf initramfs-run
    cp -a initramfs initramfs-run
    cd initramfs-run/app
    tar xf ${APP_NAME}.tar
    rm -rf ${APP_NAME}.tar
    cp -a $BASEDIR/conf/app.yml workplace/apploader/conf
    cp -a $BASEDIR/conf/conker/backend/conf workplace/app/conker/backend
    tar czf ../${APP_NAME}.tar .
    cd $BASEDIR/initramfs-run
    rm -rf ./app
    mkdir ./app
    mv ${APP_NAME}.tar ./app
    find . |cpio -o -H newc |gzip > $BASEDIR/${IMAGE_NAME}.img
}

function measurement() {
    echo "not support yet..."
}

function run() {
     Mode=$1
     mkdir -p ${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/
     cp -a $BASEDIR/${IMAGE_NAME}.img ${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/

     if [ ! -f ${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/disk/disk1.img ];then
         mkdir -p ${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/disk
         qemu-img create ${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/disk/disk1.img ${CSV_ENCRYPTED_DISK_SIZE1}
     fi

     if [ x$Mode == "xhost" ]; then
         echo "network use $Mode "
         NETCONFIG="-netdev bridge,br=virbr0,id=net0 -device virtio-net-pci,netdev=net0,mac=${CSV_MAC}"
     else
         echo "network use $Mode "
         NETCONFIG="-netdev bridge,br=br0,id=n1 -device virtio-net-pci,netdev=n1,iommu_platform=on,disable-legacy=on,mac=${CSV_MAC}"
     fi


   command="${QEMU_FOR_CSV_PATH} -kernel ${CSV_BASE_DIR}/kernel/bzImage-6.8.4 -append \"root=/dev/ram0 init=/init rootfstype=ramfs net.ifnames=0 biosdevname=0\"  \
       -initrd ${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/${IMAGE_NAME}.img -smp ${CSV_CPUS} -m ${CSV_MEMORY} -accel kvm -cpu host \
       -bios /usr/share/ovmf/OVMF.fd \
       -object tdx-guest,id=tdx \
       -nodefaults \
       -chardev stdio,id=mux,mux=on,logfile=${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/vm.log \
       -device virtio-serial,romfile= -device virtconsole,chardev=mux -monitor chardev:mux  -serial chardev:mux\
       -device vhost-vsock-pci,guest-cid=${GUEST_CID} \
       -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off -vnc ${VNC_PORT} \
       -drive file=${CSV_BASE_DIR}/runtime/${INSTALL_DIR}/disk/disk1.img,if=virtio \
      ${NETCONFIG} "

   OS_TYPE=`cat /etc/os-release |grep -w ID |awk -F= '{print $2}'`
   case "$OS_TYPE" in
      \"anolis\")
       preStartCmd="firewall-cmd --reload"
       ;;
      ubuntu)
       preStartCmd=""
        ;;
      centos)
        preStartCmd=""
        ;;
      *)
     preStartCmd=""
        ;;
     esac

    echo -e "[INFO] generate service file of ${CVM_NAME}"
      cat >/etc/systemd/system/${CVM_NAME}.service <<EOF
[Unit]
Description=${CVM_NAME}
[Service]
ExecStartPre=${preStartCmd}
ExecStart=${command} 
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
Delegate=yes
KillMode=process
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# start server
systemctl enable ${CVM_NAME}.service
systemctl restart ${CVM_NAME}.service
}


function stop() {
  systemctl stop ${CVM_NAME}.service
}

case $1 in
	setconf)
	    SetConf
	;;
	measure)
	   measurement
	;;
	run)
	  run $2
	;;
  down)
    stop
esac