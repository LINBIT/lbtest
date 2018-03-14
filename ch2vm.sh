#!/bin/bash

die() {
	>&2 echo "$1"
	exit 1
}

ARGC=$#
if [[ $ARGC -lt 3 || $ARGC -gt 4 ]]; then die 'dist kernel vmnr "[payload1;payload2;...]"'; fi

[ "$(id -u)" = "0" ] || die "Run this script as root"

for i in "id_rsa" "id_rsa.pub" "authorized_keys"; do
	[ -f ./scripts/ssh/$i ] || die "$i does not exist"
done

# VARIABLE SETUP
: "${TMP:=/tmp}"
: "${NFSSERVER:=10.43.57.42}"
: "${IPBASE:=10.43.70}"
: "${NETMASK:=255.255.0.0}"
: "${GW:=10.43.1.1}"
: "${MACBASE:=52:54:57:99:99}"
: "${BASEZFS:=tank/d9ts}"

DISTNAME=$1
KERN_INITRAMFS=$2
NR=$3

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

[ "$ARGC" = 4 ] && PAYLOADS=$4 || PAYLOADS="shell"
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
shopt -s nullglob
UTILSPKG=($OVERLAY/pkgs/drbd-utils/$DISTNAME/amd64/drbd-utils*.${FORMAT})
[ "${#UTILSPKG[*]}" = "1" ] || die "UTILSPKG did not exactly match 1 file"
EXXEPKG=($OVERLAY/pkgs/exxe/$DISTNAME/amd64/exxe*.${FORMAT})
[ "${#EXXEPKG[*]}" = "1" ] || die "EXXEPKG did not exactly match 1 file"
LOGSCANPKG=($OVERLAY/pkgs/logscan/$DISTNAME/amd64/logscan*.${FORMAT})
[ "${#LOGSCANPKG[*]}" = "1" ] || die "LOGSCANPKG did not exactly match 1 file"
TESTSPKG=($OVERLAY/pkgs/drbd9-tests/drbd9-tests.tar.gz)
[ "${#TESTSPKG[*]}" = "1" ] || die "TESTSPKG did not exactly match 1 file"
KERNELPKG=($OVERLAY/pkgs/drbd/$DISTNAME/amd64/$KERN_INITRAMFS/$KPREFIX*.${FORMAT})
[ "${#KERNELPKG[*]}" = "1" ] || die "KERNELPKG did not exactly match 1 file"
shopt -u nullglob
EXTRAPKGS=$OVERLAY/extra/$DISTNAME

# RCK's version of double rot13:
MD5OVERALL="${DISTNAME}-${KERN_INITRAMFS}" # "seed", see comment below why I do that
for pkg in "$UTILSPKG" "$EXXEPKG" "$LOGSCANPKG" "$TESTSPKG" "$KERNELPKG"; do
	MD5PKG=$(md5sum "$pkg" | cut -f1 -d' ')
	MD5OVERALL=${MD5OVERALL}-${MD5PKG}
	MD5OVERALL=$(echo "$MD5OVERALL" | md5sum | cut -f1 -d' ')
done

STATICZFS=$BASEZFS/${ZFSDISTNAME}-${KERN_INITRAMFS}
STATICMNT=/$STATICZFS
STATICSNAP=${STATICZFS}@static

# there could be for example multiple xenials with different kernels but the same pkg md5sum if we only count pkgs
# Strictly speaking this can be handled by:
# - including the distri + kernel in the overall md5sum
# - or by including it in the PKG variables and therefore the ZFS names
# here we do both, especually including it into the ZFS name (this makes it a bit easier to read as a human)
PKGZFS=${STATICZFS}-${MD5OVERALL}
PKGMNT=/$PKGZFS
PKGSNAP=${PKGZFS}@pkgs

gen_uuid() {
	cat /proc/sys/kernel/random/uuid
}

create_vm_base() {
	echo "Creating VM Base"
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
			cp "$EXTRAPKGS"/*.${FORMAT} "$STATICMNT"/
			chroot "$STATICMNT" /bin/sh -c "$INST_UTIL /*.${FORMAT}; rm -f /*.${FORMAT}"
		fi
		case "$FORMAT" in
			"rpm")
				RPMPKG="e2fsprogs kmod iptables fio lvm2 rsyslog openssh-server"
				[ "$DISTNAME" = "rhel6.0" ] && RPMPKG="$RPMPKG python-argparse"
				chroot "$STATICMNT" /bin/sh -c "yum install -y $RPMPKG"
				# PS1="IN $STATICMNT# " chroot $STATICMNT /bin/bash -l -i
				;;
			"deb")
				chroot "$STATICMNT" /bin/sh -c "apt -y update && apt -y install rsyslog openssh-server iputils-ping kmod fio iptables thin-provisioning-tools"
				chroot "$STATICMNT" /bin/sh -c "apt -y install vim-nox";
				[ -n "$INSTALLVIM" ] && chroot "$STATICMNT" /bin/sh -c "apt -y install vim-nox";
				;;
		esac
		umount "${STATICMNT}/proc"
		umount "${STATICMNT}/dev"
		zfs umount "$STATICZFS"
		sync
		zfs snapshot "$STATICSNAP"
	fi

	# this builds on the STATICSNAP, using a second lock does not really make sense here
	if ! zfs list -t snapshot "$PKGSNAP"; then
		echo "Creating snapshot containing volatile packages (drbd9, utils, test suite) image"
		zfs clone "$STATICSNAP" "$PKGZFS"
		cp "$UTILSPKG" "$KERNELPKG" "$EXXEPKG" "$LOGSCANPKG" "$TESTSPKG" "${PKGMNT}/"
		echo "$(gen_uuid) - PKGS $MD5OVERALL" >> "${PKGMNT}/history.txt"
		mount --bind /proc "${PKGMNT}/proc"
		mount --bind /dev  "${PKGMNT}/dev"
		chroot "$PKGMNT" /bin/sh -c "no_initramfs=1 $INST_UTIL /*.${FORMAT}; rm -f /*.${FORMAT}"
		chroot "$PKGMNT" /bin/sh -c "tar xvf /drbd9-tests.tar.gz && cd /drbd9-tests && make && make install; rm -f /drbd9-tests.tar.gz"
		# PS1="IN $PKGMNT# " chroot $PKGMNT /bin/bash -l -i
		umount "${PKGMNT}/proc"
		umount "${PKGMNT}/dev"
		zfs umount "$PKGZFS"
		sync
		zfs snapshot "$PKGSNAP"
	fi
	) 9> /var/lock/"$DISTNAME"-"$KERN_INITRAMFS".lock

	zfs clone "$PKGSNAP" "$PERVMROOTZFS" || die "clone $PKGSNAP $PERVMROOTZFS did not work"
}

[ -f "${PERVMROOTMNT}/.resume" ] || create_vm_base

DATE=$(date +%F_%s)
zfs set aux:lastused="$DATE" "$PKGSNAP"
# use lastused=$(zfs get -o value -H aux:lastused $PKGSNAP)
echo "$(gen_uuid) - $VMNAME started: $DATE" >> "${PERVMROOTMNT}/history.txt"
zfs set sharenfs=on "$PERVMROOTZFS"

### PER VM SETUP
# copying this might look weird, but I want to keep it in this repo...
cp ./scripts/init.sh "$PERVMROOTMNT"/sbin/init.sh
chmod +x ./scripts/init.sh "$PERVMROOTMNT"/sbin/init.sh
cp ./scripts/ssh/id_rsa "$PERVMROOTMNT"/etc/ssh/ssh_host_rsa_key

mkdir -p "$PERVMROOTMNT"/root/.ssh
chmod 700 "$PERVMROOTMNT"/root/.ssh
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
	cp ./scripts/service.fake $PERVMROOTMNT/usr/sbin/service
	chmod +x "${PERVMROOTMNT}/usr/sbin/service"
fi

cp -r ./scripts/payloads "${PERVMROOTMNT}/"

for i in $(seq 1 54); do
	echo "${IPBASE}.$((i + IPOFFSET)) vm-$i"  >> "${PERVMROOTMNT}/etc/hosts"
done

trap : TERM HUP
(
trap - TERM HUP
qemu-system-x86_64 \
	-m 768M \
	-display none \
	-nodefconfig -no-user-config -nodefaults \
	\
	-name "$VMNAME" -machine accel=kvm:tcg -enable-kvm \
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
	-kernel "$LINUX" -initrd "$INITRD" -append "$APPEND"
)

if [ ! -f "${PERVMROOTMNT}/.resume" ]; then
	zfs unshare "$PERVMROOTZFS"
	zfs set sharenfs=off "$PERVMROOTZFS"
	SECONDS=0
	if ! zfs destroy "$PERVMROOTZFS" ; then
		echo 0 > /proc/fs/nfsd/threads
		while sleep 1; do zfs destroy -v "$PERVMROOTZFS" && break; done
		echo 20 > /proc/fs/nfsd/threads
	fi
fi
