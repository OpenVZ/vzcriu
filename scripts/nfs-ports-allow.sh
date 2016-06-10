#!/bin/bash

[[ "post-network-lock" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

if [ ! -n "$CRTOOLS_INIT_PID" ]; then
	echo "CRTOOLS_INIT_PID environment variable is not set"
	exit 1
fi

CRTOOLS_IPTABLES_TABLE="CRIU"
if [ ! -n "$CRTOOLS_IPTABLES_TABLE" ]; then
	echo "CRTOOLS_IPTABLES_TABLE environment variable is not set"
	exit 1
fi

NS_ENTER=/bin/nsenter
[ ! -x ${NS_ENTER} ] || NS_ENTER=/usr/bin/nsenter

if [ ! -x ${NS_ENTER} ]; then
	echo "${NS_ENTER} binary not found"
	exit 2
fi

JOIN_CT="${NS_ENTER} -t $CRTOOLS_INIT_PID -m -u -p -n"

${JOIN_CT} test -e /proc/self/net/nfsfs || exit 0

servers=$($JOIN_CT cat /proc/self/net/nfsfs/servers | sed -e '1d' | awk '{ printf $5" ";}')

[ -n "$servers" ] || exit 0

function add_accept_rules {
	local server=$1
	local port=$2

	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -d $server --dport $port -j ACCEPT &&
	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p udp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p udp -d $server --dport $port -j ACCEPT 
}

function iptables_allow_nfs_ports {
	local server=$1
	local ports=$2

	for p in $ports; do
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

	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p udp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p udp -d $server --dport $port -j ACCEPT &&
	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -s $server --sport $port -j ACCEPT &&
	${JOIN_CT} iptables -I ${CRTOOLS_IPTABLES_TABLE} -p tcp -d $server --dport $port -j ACCEPT 
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
