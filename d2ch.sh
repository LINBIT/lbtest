#!/bin/bash

die() {
	>&2 echo "$1"
	exit 1
}

dockerrm() {
	[ -n "$TMPDOCKER" ] && { echo "Removing $TMPDOCKER"; docker rm "$TMPDOCKER"; }
}

ARGC=$#
if [[ $ARGC != 1  ]]; then die "dist:tag (e.g., rhel7.0:latest)"; fi

[ "$(id -u)" = "0"  ] || die "Run this script as root"

IMAGETAG=$1
IMAGE=$(echo "$IMAGETAG" | cut -f1 -d':')
TAG=$(echo "$IMAGETAG" | cut -f2 -d':')
DOCKERIMAGE="dc-${IMAGE}-amd64"
DOCKERIMAGETAG="${DOCKERIMAGE}:${TAG}"
DOCKERIMAGETAGFS="${DOCKERIMAGE}-${TAG}"

CHROOTZFS="tank/d9ts/$DOCKERIMAGETAGFS"
CHROOTMNT="/$CHROOTZFS"
CHROOTMNT="$(echo -e "${CHROOTMNT}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
[ "$CHROOTMNT" != "/" ] || die "No, we don't extract to /, we already did that ;)"
CHROOTSNAP="${CHROOTZFS}@rootfs"

echo "creating zfs $CHROOTZFS"
zfs create "$CHROOTZFS" || die "Could not create $CHROOTZFS"

TMPDOCKER=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 10 | head -n1)
echo "docker running $DOCKERIMAGETAG as $TMPDOCKER"
docker run --name "$TMPDOCKER" "$DOCKERIMAGETAG" /bin/sh || die "Could not run docker image"
trap dockerrm EXIT

echo "exporting $TMPDOCKER to $CHROOTMNT"
docker export "$TMPDOCKER" | tar xf - --exclude=dev/* -C "$CHROOTMNT" || die "Could not export container"

echo "writing history file"
echo "$(cat /proc/sys/kernel/random/uuid) - $DOCKERIMAGETAG" > "$CHROOTMNT"/history.txt

echo "Fixing resolv.conf"
echo "nameserver 8.8.8.8" > "${CHROOTMNT}/etc/resolv.conf"
chmod 644 "${CHROOTMNT}/etc/resolv.conf"

sync

echo "zfs creating snapshot $CHROOTSNAP"
zfs snapshot "$CHROOTSNAP" || die "Could not create snapshot"

echo "Successfully created rootfs and snapshot"
