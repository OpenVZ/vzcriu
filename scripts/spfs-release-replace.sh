#!/bin/bash

[[ "post-resume" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

set -o pipefail

if [ -z "$SPFS_MANAGER_SOCK" ]; then
	echo "SPFS_MANAGER_SOCK environment variable is not set"
	exit 1
fi

[ -e $SPFS_MANAGER_SOCK ] || exit 0

if [ ! -S "$SPFS_MANAGER_SOCK" ]; then
	echo "$SPFS_MANAGER_SOCK is not a socket"
	exit 1
fi

SPFS_CLIENT="/usr/sbin/spfs-client"

if [ ! -x "$SPFS_CLIENT" ]; then
	echo "Filed to find executable /usr/sbin/spfs-client"
	exit 1
fi

$SPFS_CLIENT manage "replace;all;mode=release" --socket-path $SPFS_MANAGER_SOCK > /dev/null
exit $?
