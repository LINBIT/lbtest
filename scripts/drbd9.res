#!/bin/bash

die() {
	>&2 echo "$1"
	exit 1
}

help() {
cat <<EOF
$(basename "$0"):
   -n | --node: node name and IP (e.g., node1:1.2.3.4)
   -m | --minor: minor number of the first volume (default: 10)
   -r | --res: resource name (default: 'r0')
   -p | --pool: pool name (as in /dev/\$pool/\$res; default: drbdpool)
        --port: port number (default: 7000)
   -s | --size: size of the volumes (in LVM units, e.g., 10M)
   -v | --volumes: number of volumes (default: 1)
   -h | --help: Print help and exit
EOF
        exit "$1"

}

gen_res() {
	echo "resource $RES {"
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

get_opts() {
	OPTS=$(getopt -o hm:n:p:r:s:v: --long help,minor:,node:,res:,size:,pool:,volumes: -n 'parse-options' -- "$@")
	eval set -- "$OPTS"

	NODES=(); IPS=();
	POOL="drbdpool"; RES="r0"; VOLUMES="1"; MINOR="10"; SIZE="10M"; PORT="7000";

	while true; do
		case "$1" in
			-r | --res) RES="$2"; shift; shift;;
			-v | --volumes) VOLUMES="$2"; shift; shift;;
			-p | --pool) POOL="$2"; shift; shift;;
			-s | --size) SIZE="$2"; shift; shift;;
			     --port) PORT="$2"; shift; shift;;
			-m | --minor) MINOR="$2"; shift; shift;;
			-n | --node) add_node "$2"; shift; shift;;
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
