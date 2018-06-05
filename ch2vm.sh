#!/bin/bash

die() {
	>&2 echo "$1"
	exit 1
}

help() {
cat <<EOF
$(basename $0)
   -d | --distribution: Distribution to boot
   -h | --help: Print help and exit
        --jdir: Jenkins directory to store test logs
        --jtest: Jenkins name of test
   -k | --kernel: Kernel to boot
   -p | --payloads: Payloads (single string, default: "shell")
   -s | --suite: Test suite to run (default: "drbd9")
   -v | --vm-nr: Number of VM (uint, e.g., 23)

'--jdir' and '--jtest' are usually passed by 'vmshed'
EOF
	exit "$1"
}

getopts() {
	[ "$(id -u)" = "0" ] || die "Run this script as root"

	OPTS=$(getopt -o d:hk:p:s:v: --long distribution:,help,jdir:,jtest:,kernel:,payloads:,suite:,vm-nr: -n 'parse-options' -- "$@")
	[ $? = 0 ] || die "Failed parsing options."

	eval set -- "$OPTS"

	DISTNAME=""; KERN_INITRAMFS=""; NR=""; HELP="";
	JENKINS_DIR=""; JENKINS_TEST="";
	PAYLOADS="shell"; SUITE="drbd9";

	while true; do
		case "$1" in
			-d | --distribution ) DISTNAME="$2"; shift; shift ;;
			-h | --help ) HELP=true; shift ;;
			--jdir ) JENKINS_DIR="$2"; shift; shift ;;
			--jtest ) JENKINS_TEST="$2"; shift; shift ;;
			-k | --kernel ) KERN_INITRAMFS="$2"; shift; shift ;;
			-p | --payloads ) PAYLOADS="$2"; shift; shift ;;
			-s | --suite ) SUITE="$2"; shift; shift ;;
			-v | --vm-nr ) NR="$2"; shift; shift ;;
			-- ) shift; break ;;
			* ) break ;;
		esac
	done

	[ "$HELP" = "true" ] && help 0
	[ -z "$DISTNAME" ] || [ -z "$KERN_INITRAMFS" ] || [ -z "$NR" ] && help 1
}

# VARIABLE SETUP
: "${TMP:=/tmp}"
: "${NFSSERVER:=10.43.57.42}"
: "${IPBASE:=10.43.70}"
: "${NETMASK:=255.255.0.0}"
: "${GW:=10.43.1.1}"
: "${MACBASE:=52:54:57:99:99}"
: "${BASEZFS:=tank/d9ts}"

for i in "id_rsa" "id_rsa.pub" "authorized_keys"; do
	[ -f ./scripts/ssh/$i ] || die "$i does not exist"
done

getopts "$@"

NEEDS_CLEANUP=no
SUICIDE=no

VMNAME=vm-$NR
IPOFFSET=200
IPL=$((IPOFFSET + NR))
[ $IPL -lt 255 ] || die "IP for VM too large ($IPL)"
IP=${IPBASE}.${IPL}
MAC=$MACBASE:$(printf "%02x" "$NR")

BASEMNT=/$BASEZFS

ZFSDISTNAME=dc-${DISTNAME}-amd64

CHROOTZFS=$BASEZFS/${ZFSDISTNAME}-latest
# CHROOTMNT=/$CHROOTZFS
CHROOTSNAP=${CHROOTZFS}@rootfs
if ! zfs list -t snapshot "$CHROOTSNAP"; then die "CHROOTSNAP ($CHROOTSNAP) does not exist"; fi

PERVMROOTZFS=$BASEZFS/$VMNAME
PERVMROOTMNT=/${PERVMROOTZFS}

BLKNAME="blk-${VMNAME}"
BLKZFS="${BASEZFS}/${BLKNAME}"
BLKOPT=""
BLKSIZE=""
BLKTHIN=""
for o in $(echo $PAYLOADS | tr ";" "\n"); do
	BLKTHIN=$(echo "$o" | grep "^lvm" | grep -o "thin")
	[ -n "$BLKTHIN" ] && BLKTHIN="-s"
	BLKSIZE=$(echo "$o" | grep "^lvm" | grep -o "bd=.*" | cut -f1 -d':' | cut -f2 -d'=')
	[ -n "$BLKSIZE" ] && break
done
[ -n "$BLKSIZE" ] && BLKOPT="-drive format=raw,discard=unmap,file=/dev/zvol/${BLKZFS}"

# nolock? local_lock=all?
NFSOPTS="rsize=16384,wsize=16384,timeo=6,retrans=30,nolock"

# setup per distribution stuff
# be very careful with these options, distibutions SUCK, eg
# if PEER set on rhel7, it does not ping
# keep NIF on xenial empty
case "$DISTNAME" in
	ubuntu-*|debian-*) FORMAT="deb"; INST_UTIL="dpkg -i"; INST_UTILOPTS="--force-overwrite"; KPREFIX="drbd-module-$LB_KERNEL"; PEER=$NFSSERVER; APPEND="root=/dev/nfs nfsroot=$NFSSERVER:$PERVMROOTMNT,$NFSOPTS";;
	rhel*) FORMAT="rpm"; INST_UTIL="yum install -y"; KPREFIX="kmod-drbd"; NIF="eth0"; APPEND="selinux=0 enforce=0 ifname=$NIF:$MAC bootdev=$NIF root=nfs:$NFSSERVER:$PERVMROOTMNT:${NFSOPTS},vers=3";;
	sles*) FORMAT="rpm"; INST_UTIL="rpm -i"; KPREFIX="drbd-kmp-default";;
	*) die "$DISTNAME is not valid/unknown";;
esac
APPEND="$APPEND ip=$IP:$PEER:$GW:$NETMASK:$VMNAME:$NIF:off rootfstype=nfs rw console=ttyS0 LB_DIST=$DISTNAME LB_KERNEL=$KERN_INITRAMFS LB_PAYLOADS=$PAYLOADS LB_IP=$IP net.ifnames=0 init=/sbin/init.sh"

INITRD=$BASEMNT/kis/${ZFSDISTNAME}-${KERN_INITRAMFS}.initrd
LINUX=$BASEMNT/kis/${ZFSDISTNAME}-${KERN_INITRAMFS}.linux
LINUXPKGNAME=${ZFSDISTNAME}-${KERN_INITRAMFS}.${FORMAT}
LINUXPKG=$BASEMNT/kis/$LINUXPKGNAME

OVERLAY=$BASEMNT/overlay

UTILSPKG=""; EXXEPKG=""; LOGSCANPKG=""; TESTSPKG=""; KERNELPKG="";
LSCLIENTPKG=""; LSSERVERPKG="";
shopt -s nullglob
KERNELPKG=($OVERLAY/pkgs/drbd/$DISTNAME/amd64/$KERN_INITRAMFS/$KPREFIX*.${FORMAT})
[ "${#KERNELPKG[*]}" = "1" ] || die "KERNELPKG did not exactly match 1 file"
UTILSPKG=($OVERLAY/pkgs/drbd-utils/$DISTNAME/amd64/drbd-utils*.${FORMAT})
[ "${#UTILSPKG[*]}" = "1" ] || die "UTILSPKG did not exactly match 1 file"
case "$SUITE" in
	drbd9)
		TESTSPKG=($OVERLAY/pkgs/drbd9-tests/drbd9-tests.tar.gz)
		[ "${#TESTSPKG[*]}" = "1" ] || die "TESTSPKG did not exactly match 1 file"
		EXXEPKG=($OVERLAY/pkgs/exxe/$DISTNAME/amd64/exxe*.${FORMAT})
		[ "${#EXXEPKG[*]}" = "1" ] || die "EXXEPKG did not exactly match 1 file"
		LOGSCANPKG=($OVERLAY/pkgs/logscan/$DISTNAME/amd64/logscan*.${FORMAT})
		[ "${#LOGSCANPKG[*]}" = "1" ] || die "LOGSCANPKG did not exactly match 1 file"
		;;
	linstor)
		TESTSPKG=($OVERLAY/pkgs/linstor-tests/linstor-tests.tar.gz)
		[ "${#TESTSPKG[*]}" = "1" ] || die "TESTSPKG did not exactly match 1 file"
		LSCLIENTPKG=($OVERLAY/pkgs/linstor-client/$DISTNAME/amd64/linstor-client*.${FORMAT})
		[ "${#LSCLIENTPKG[*]}" = "1" ] || die "LSCLIENTPKG did not exactly match 1 file"
		LSSERVERPKG=($OVERLAY/pkgs/linstor-server/$DISTNAME/amd64/linstor-server*.${FORMAT})
		[ "${#LSSERVERPKG[*]}" = "1" ] || die "LSSERVERPKG did not exactly match 1 file"
		;;
esac
shopt -u nullglob
ALLPKGS=(${UTILSPKG[0]} ${EXXEPKG[0]} ${LOGSCANPKG[0]} ${TESTSPKG[0]} ${KERNELPKG[0]} ${LSCLIENTPKG[0]} ${LSSERVERPKG[0]})
EXTRAPKGS=$OVERLAY/extra/$DISTNAME

# RCK's version of double rot13:
PKGSONLY=""
for pkg in ${ALLPKGS[*]}; do
	[ -z "$pkg" ] && continue
	MD5PKG=$(md5sum "$pkg" | cut -f1 -d' ')
	PKGSONLY="${PKGSONLY}-${MD5PKG}"
	PKGSONLY=$(echo "$PKGSONLY" | md5sum | cut -f1 -d' ')
done

STATICZFS=$BASEZFS/${ZFSDISTNAME}-${KERN_INITRAMFS}
STATICMNT=/$STATICZFS
STATICSNAP=${STATICZFS}@static

# there could be for example multiple xenials with different kernels but the same pkg md5sum if we only count pkgs
# Strictly speaking this can be handled by:
# - including the distri + kernel in the overall md5sum
# - or by including it in the PKG variables and therefore the ZFS names
# here we do both, especually including it into the ZFS name (this makes it a bit easier to read as a human)
MD5OVERALL=$(echo "$PKGSONLY-${DISTNAME}-${KERN_INITRAMFS}" | md5sum | cut -f1 -d' ')
PKGZFS=${STATICZFS}-${MD5OVERALL}
PKGMNT=/$PKGZFS
PKGSNAP=${PKGZFS}@pkgs

gen_uuid() {
	cat /proc/sys/kernel/random/uuid
}

clean_up() {
	if [ -n "$JENKINS_DIR" ] && [ -n "$JENKINS_TEST" ]; then
		case "$SUITE" in
			drbd9)
				LOGDIR="${PERVMROOTMNT}/drbd9-tests/tests/log/${JENKINS_TEST}-latest"
				;;
			linstor)
				LOGDIR="${PERVMROOTMNT}/linstor-tests/tests/log/${JENKINS_TEST}-latest"
				;;
		esac
		(cd "$LOGDIR" && mkdir -p "$JENKINS_DIR" && tar -czf "${JENKINS_DIR}/logs.tar.gz" . )
	fi

	[ -f "${PERVMROOTMNT}/.resume" ] && NEEDS_CLEANUP=no
	if [ "$NEEDS_CLEANUP" = "yes" ]; then
		[ -n "$BLKOPT" ] && zfs destroy "$BLKZFS"
		zfs unshare "$PERVMROOTZFS"
		zfs set sharenfs=off "$PERVMROOTZFS"
		SECONDS=0
		if ! zfs destroy "$PERVMROOTZFS" ; then
			echo 0 > /proc/fs/nfsd/threads
			while sleep 1; do zfs destroy -v "$PERVMROOTZFS" && break; done
			echo 20 > /proc/fs/nfsd/threads
		fi
	fi
}

got_sig() {
	SUICIDE=yes
}

create_vm_base() {
	echo "Creating VM Base"
	trap got_sig TERM HUP  # this is the "critical section". from here one we don't want to be interruped
	NEEDS_CLEANUP=yes
	(
	flock -w 600 9 || die "flock failed/timeout"
	# does the snapshot containing the kernel-image (for .ko deps) exist?
	if ! zfs list -t snapshot "$STATICSNAP"; then
		echo "Creating snapshot containing kernel image (and 'non-volatile' packages)"
		zfs clone "$CHROOTSNAP" "$STATICZFS"
		cp "$LINUXPKG" "${STATICMNT}/"
		echo "$(gen_uuid) - KERNEL $KERN_INITRAMFS" >> "${STATICMNT}/history.txt"
		mount --bind /proc "${STATICMNT}/proc"
		mount --bind /dev "${STATICMNT}/dev"
		chroot "$STATICMNT" /bin/sh -c "$INST_UTIL /$LINUXPKGNAME; rm -f /$LINUXPKGNAME"
		if [ -d "$EXTRAPKGS" ]; then
			cp "$EXTRAPKGS"/*.${FORMAT} "${STATICMNT}/"
			chroot "$STATICMNT" /bin/sh -c "$INST_UTIL /*.${FORMAT}; rm -f /*.${FORMAT}"
		fi

		# static dependencies
		case "$FORMAT" in
			"rpm")
				RPMPKG="e2fsprogs kmod iptables fio lvm2 rsyslog openssh-server java-1.8.0-openjdk-headless"
				[ "$DISTNAME" = "rhel6.0" ] && RPMPKG="$RPMPKG python-argparse"
				[ "$DISTNAME" = "rhel7.0" ] && RPMPKG="$RPMPKG protobuf-python python-setuptools"
				chroot "$STATICMNT" /bin/sh -c "yum install -y $RPMPKG"
				# PS1="IN $STATICMNT# " chroot $STATICMNT /bin/bash -l -i
				;;
			"deb")
				DEBPKG="rsyslog openssh-server iputils-ping iproute2 kmod fio iptables lvm2 thin-provisioning-tools default-jre-headless python-natsort python-protobuf"
				chroot "$STATICMNT" /bin/sh -c "apt-get -y update && apt-get install -yf && apt-get -y install $DEBPKG"
				chroot "$STATICMNT" /bin/sh -c "apt-get -y install vim-nox"
				[ -n "$INSTALLVIM" ] && chroot "$STATICMNT" /bin/sh -c "apt-get -y install vim-nox";
				;;
		esac

		umount "${STATICMNT}/proc"
		umount "${STATICMNT}/dev"
		zfs umount "$STATICZFS"
		sync
		zfs snapshot "$STATICSNAP"
	fi

	# this builds on the STATICSNAP, using a second lock does not really make sense here
	# we want that to happen fast, so all dependencies have to be already installed!
	if ! zfs list -t snapshot "$PKGSNAP"; then
		echo "Creating snapshot containing volatile packages (drbd9, utils, test suite) image"
		zfs clone "$STATICSNAP" "$PKGZFS"
		for pkg in ${ALLPKGS[*]}; do
			[ -z "$pkg" ] && continue
			cp "$pkg" "${PKGMNT}/"
		done
		echo "$(gen_uuid) - PKGS ${PKGSONLY}/${MD5OVERALL}" >> "${PKGMNT}/history.txt"
		mount --bind /proc "${PKGMNT}/proc"
		mount --bind /dev  "${PKGMNT}/dev"
		if echo "$INST_UTIL" | grep -q "yum"; then INST_UTIL="$INST_UTIL -C"; fi
		chroot "$PKGMNT" /bin/sh -c "no_initramfs=1 $INST_UTIL /*.${FORMAT}; rm -f /*.${FORMAT}"
		case "$SUITE" in
			drbd9)
				chroot "$PKGMNT" /bin/sh -c "tar xvf /drbd9-tests.tar.gz && cd /drbd9-tests && make && make install; rm -f /drbd9-tests.tar.gz"
				;;
			linstor)
				chroot "$PKGMNT" /bin/sh -c "tar xvf /linstor-tests.tar.gz && cd /linstor-tests; rm -f /linstor-tests.tar.gz"
				;;
		esac
		# PS1="IN $PKGMNT# " chroot $PKGMNT /bin/bash -l -i
		umount "${PKGMNT}/proc"
		umount "${PKGMNT}/dev"
		zfs umount "$PKGZFS"
		sync
		zfs snapshot "$PKGSNAP"
	fi
	) 9> /var/lock/"$DISTNAME"-"$KERN_INITRAMFS".lock

	zfs clone "$PKGSNAP" "$PERVMROOTZFS" || die "clone $PKGSNAP $PERVMROOTZFS did not work"
	if [ -n "$BLKOPT" ]; then
		zfs create -b $(( 4 * 2**10  )) -V "$BLKSIZE" "$BLKZFS" $BLKTHIN || die "could not create zfs block device $BLKZFS"
	fi
}

trap clean_up EXIT

[ -f "${PERVMROOTMNT}/.resume" ] || create_vm_base

DATE=$(date +%F_%s)
zfs set aux:lastused="$DATE" "$PKGSNAP"
# use lastused=$(zfs get -o value -H aux:lastused $PKGSNAP)
echo "$(gen_uuid) - $VMNAME started: $DATE" >> "${PERVMROOTMNT}/history.txt"
zfs set sharenfs=on "$PERVMROOTZFS"

### PER VM SETUP
# copying this might look weird, but I want to keep it in this repo...
cp ./scripts/init.sh "${PERVMROOTMNT}/sbin/init.sh"
chmod +x ./scripts/init.sh "${PERVMROOTMNT}/sbin/init.sh"
cp ./scripts/ssh/id_rsa "${PERVMROOTMNT}/etc/ssh/ssh_host_rsa_key"

mkdir -p "${PERVMROOTMNT}/root/.ssh"
chmod 700 "${PERVMROOTMNT}/root/.ssh"
cp ./scripts/ssh/id_rsa{,.pub} "${PERVMROOTMNT}/root/.ssh/"
cat ./scripts/ssh/id_rsa.pub > "${PERVMROOTMNT}/root/.ssh/authorized_keys"
cat ./scripts/ssh/authorized_keys >> "${PERVMROOTMNT}/root/.ssh/authorized_keys"
echo 'Host *' > "${PERVMROOTMNT}/root/.ssh/config"
echo '    StrictHostKeyChecking no' >> "${PERVMROOTMNT}/root/.ssh/config"
mkdir -p "${PERVMROOTMNT}/usr/local/bin"
cat <<EOF >"${PERVMROOTMNT}/usr/local/bin/shutdown"
#!/bin/sh

while true; do
	echo o > /proc/sysrq-trigger
	sleep 5
done
EOF
chmod +x "${PERVMROOTMNT}/usr/local/bin/shutdown"

if [ "$DISTNAME" = "rhel7.0" ]; then
	mv "${PERVMROOTMNT}"/usr/sbin/service{,.real}
	cp ./scripts/service.fake "${PERVMROOTMNT}/usr/sbin/service"
	chmod +x "${PERVMROOTMNT}/usr/sbin/service"
fi

cp -r ./scripts/payloads "${PERVMROOTMNT}/"

for i in $(seq 1 54); do
	echo "${IPBASE}.$((i + IPOFFSET)) vm-$i"  >> "${PERVMROOTMNT}/etc/hosts"
done

[ "$SUICIDE" = "yes" ] && exit 1

(
trap - TERM HUP
qemu-system-x86_64 \
	-name "$VMNAME" -machine accel=kvm:tcg -enable-kvm \
	\
	-m 768M \
	-display none \
	-nodefconfig -no-user-config -nodefaults \
	\
	-device virtio-rng-pci \
	\
	-chardev stdio,id=charserial0,signal=off \
	-device isa-serial,chardev=charserial0,id=serial0 \
	\
	-chardev socket,id=con0,path="${TMP}/${VMNAME}-console.pipe,server,nowait" \
	-mon chardev=con0,mode=readline \
	\
	-net nic,macaddr="$MAC" -net bridge,br=br0 \
	\
	-kernel "$LINUX" -initrd "$INITRD" -append "$APPEND" $BLKOPT
)
