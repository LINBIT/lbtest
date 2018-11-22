#!/bin/bash

export PATH=/usr/local/bin:/usr/sbin:$PATH

export TZ=UTC

### MAIN ###
# yes, we assume that we only have modern distributions...
# otherwise things like LVM gets nasty
/lib/systemd/systemd-udevd --daemon || /sbin/udevd --daemon
udevadm trigger

echo "##################"
echo "### VM HISTORY ###"
echo "##################"
cat /history.txt

# parse options we got kernel params
for o in $(cat /proc/cmdline) ; do
	case "$o" in
		LB_DIST=*) export $o ;;
		LB_IP=*) export $o ;;
		LB_KERNEL=*) export $o ;;
		LB_PAYLOADS=*) export $o ;;
	esac
done

if [ "$LB_DIST" = "rhel7.0" ]; then
	/usr/lib/systemd/systemd-journald&
fi

echo "#########################"
echo "### STARTING PAYLOADS ###"
echo "#########################"
for p in $(echo $LB_PAYLOADS | tr ";" "\n"); do
	[ "$p" = "none" ] && continue
	[ "$p" = "resume" ] && { touch /.resume; continue; }
	[ "$p" = "systemd" ] && { echo "root" | passwd --stdin "root"; exec /lib/systemd/systemd; }

	x=(${p/:/ })
	p=${x[0]}
	args=${x[1]}

	# for now ignore, only simple client tests
	[ "$p" = "preplinstor" ] && continue

	echo "# Starting: $p with $args"
	sh /payloads/$p $args
done

# A simple "echo o..." isn't enough, ending init gives a PANIC
while true; do
	# echo r > /proc/sysrq-trigger
	# echo e > /proc/sysrq-trigger
	# echo i > /proc/sysrq-trigger
	# echo s > /proc/sysrq-trigger
	# echo u > /proc/sysrq-trigger
	echo o > /proc/sysrq-trigger
	sleep 5
done
