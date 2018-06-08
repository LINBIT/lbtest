#!/bin/bash

die() {
	>&2 echo "$1"
	exit 1
}

help() {
cat <<EOF
$(basename "$0"):
   -n | --node: node name and IP (e.g., -n node1:1.2.3.4)
   -m | --minor: minor number of the first volume (default: '10')
   -r | --res: resource name (default: 'r0')
   -p | --pool: pool name (as in /dev/\$pool/\$res; default: 'drbdpool')
        --port: port number (default: 7000)
   -s | --size: size of the volumes (in LVM units, e.g., '10M')
   -v | --volumes: number of volumes (default: 1)
   -o | --opt: set drbd options (e.g., -o allow-two-primaries=yes)
   -h | --help: Print help and exit
EOF
        exit "$1"

}

gen_section() {
	echo "   $1 {"
	for op in $2; do
		o=( $(echo "$op" | tr "=" " ") )
		echo "      ${o[0]} ${o[1]};"
	done
	echo "   }"
	echo ""
}

gen_res() {
	echo "resource $RES {"
	gen_section "net" "${NETOPTS[*]}"
	gen_section "disk" "${DISKOPTS[*]} ${PEEROPTS[*]}"
	gen_section "options" "${RESOPTS[*]}"
	for (( i=0 ; i<${#NODES[*]} ; i++ )); do
		echo "   on ${NODES[$i]} {"
		echo "      node-id $i;"
		echo "      address ${IPS[$i]}:${PORT};"
		for (( v=0 ; v < VOLUMES ; v++ )); do
			echo "      volume $v {"
			echo "         device minor $((MINOR + v));"
			echo "         disk /dev/${POOL}/${RES}_${v};"
			echo "         # lvcreate -L $SIZE -n${RES}_${v} ${POOL}"
			echo "         meta-disk internal;"
			echo "      }"
		done
		echo "   }"
		echo ""
	done
	echo "   connection-mesh {"
	echo "      hosts ${NODES[*]};"
	echo "   }"
	echo "}"
	echo "# drbdadm create-md $RES && drbdadm up $RES && drbdadm primary --force $RES"
}

add_node() {
	n=( $(echo "$1" | tr ":" " ") )
	NODES[${#NODES[*]}]=${n[0]}
	IPS[${#IPS[*]}]=${n[1]}
}

DSDISKO=$(drbdsetup help disk-options)
DSNETO=$(drbdsetup help new-peer) # yes, new-peer
DSPEERDO=$(drbdsetup help peer-device-options)
DSRESO=$(drbdsetup help resource-options)
set_opts() {
	o=( $(echo "$1" | tr "=" " ") )
	opt=${o[0]}
	if echo "$DSDISKO" | grep -q "$opt"; then
		DISKOPTS[${#DISKOPTS[*]}]=$1
	elif echo "$DSNETO" | grep -q "$opt"; then
		NETOPTS[${#NETOPTS[*]}]=$1
	elif echo "$DSPEERDO" | grep -q "$opt"; then
		PEEROPTS[${#PEEROPTS[*]}]=$1
	elif echo "$DSRESO" | grep -q "$opt"; then
		RESOPTS[${#RESOPTS[*]}]=$1
	else
		die "not a valid drbdsetup option: $opt"
	fi
}

get_opts() {
	OPTS=$(getopt -o hm:n:o:p:r:s:v: --long help,minor:,node:,opt:,res:,size:,pool:,volumes: -n 'parse-options' -- "$@")
	eval set -- "$OPTS"

	NODES=(); IPS=();
	POOL="drbdpool"; RES="r0"; VOLUMES="1"; MINOR="10"; SIZE="10M"; PORT="7000";
	DISKOPTS=(); NETOPTS=(); PEEROPTS=(); RESOPTS=();

	while true; do
		case "$1" in
			-r | --res) RES="$2"; shift; shift;;
			-v | --volumes) VOLUMES="$2"; shift; shift;;
			-p | --pool) POOL="$2"; shift; shift;;
			-s | --size) SIZE="$2"; shift; shift;;
			     --port) PORT="$2"; shift; shift;;
			-m | --minor) MINOR="$2"; shift; shift;;
			-n | --node) add_node "$2"; shift; shift;;
			-o | --opt) set_opts "$2"; shift; shift;;
			-h | --help) HELP=true; shift;;
			-- ) shift; break ;;
			* ) break;;
		esac
	done

	[ "$HELP" = "true" ] && help 0
	[[ ${#NODES[*]} == 0 ]] && { echo "You have to specify at least one node"; help 1; }
}

get_opts "$@"
gen_res
