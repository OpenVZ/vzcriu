#!/bin/bash

[[ "post-network-lock" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

if [ ! -n "$CRTOOLS_INIT_PID" ]; then
	echo "CRTOOLS_INIT_PID environment variable is not set"
	exit 1
fi

CRTOOLS_IPTABLES_TABLE="CRIU"

NS_ENTER=/bin/nsenter
[ -x ${NS_ENTER} ] || NS_ENTER=/usr/bin/nsenter

if [ ! -x ${NS_ENTER} ]; then
	echo "${NS_ENTER} binary not found"
	exit 2
fi

JOIN_CT="${NS_ENTER} -t $CRTOOLS_INIT_PID -u -n"

${JOIN_CT} test -e /proc/self/net/nfsfs || exit 0

if [ -z "$VEID" ]; then
	echo "VEID is not set"
	exit 1
fi

# note: pstree is frozen by criu at these point in collect_pstree()
servers=''
for vepid in $(cat /sys/fs/cgroup/ve/$VEID/tasks); do
	servers="$servers $(cat /proc/$vepid/mountinfo | awk '/ - nfs/ {print $NF}' |\
		awk -F "," '{for (i = 1; i <= NF; i++) { if ($i~"^addr="){sub(/^addr=/,"", $i); print $i}}}')"
done
servers=$(echo $servers | tr ' ' '\n' | sort -u)

[ -n "$servers" ] || exit 0

function add_accept_rules {
	local server=$1
	local port=$2

	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -d $server --dport $port -j ACCEPT &&
	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p udp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p udp -d $server --dport $port -j ACCEPT 
}

function iptables_allow_nfs_ports {
	local server=$1
	local ports=$2

	for p in $ports; do
		echo "Unmasking NFS route $s:$p"
		add_accept_rules $server $p || break
	done
}

function nfs_server_ports {
	local server=$1
	local nfs_prog=100003

	echo $($JOIN_CT rpcinfo -p $s |  grep -w "^    ${nfs_prog}" | awk '{print $4;}' | sort -u)
}

function allow_portmapper_port {
	local server=$1
	local port=111

	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p udp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p udp -d $server --dport $port -j ACCEPT &&
	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -w -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -d $server --dport $port -j ACCEPT 
}

for s in $servers; do
	allow_portmapper_port $s
	if [ $? -ne 0 ]; then
		echo "Failed to allow portmapper for "$s
		exit 3
	fi

	ports=$(nfs_server_ports $s)
	if [ -z "${ports}" ]; then
		echo "Failed to discover NFS ports on "$s
		exit 4
	fi
	iptables_allow_nfs_ports $s $ports
	if [ $? -ne 0 ]; then
		echo "Failed to allow NFS ports for "$s
		exit 5
	fi
done
