#!/bin/bash
#
# This script can be used as a workaround for systemd autofs mount migration.
# The problem is that systemd is a clever guy: before mounting of actual file
# system on top of autofs mount, it first checks that device number of autofs
# mount is equal to the one, stored in systemd internals. If they do not match,
# systemd ignores kernel request.
# The problem happens each time autofs is restored (new device number for
# autofs superblock) and can't be properly solved without some kind of "device
# namespaces", where device number can be preserved.
# But some of systemd services can be painlessly restarted. Like
# proc-sys-fs-binfmt_misc.
#
# Usage:
# criu restore <options> --action-script $(pwd)/scripts/systemd-autofs-restart.sh
#
[ "$CRTOOLS_SCRIPT_ACTION" == "post-resume" ] || exit 0

if [ -z "$CRTOOLS_INIT_PID" ]; then
	echo "CRTOOLS_INIT_PID environment variable is not set"
	exit 1
fi

if [ ! -d "/proc/$CRTOOLS_INIT_PID" ]; then
	echo "Process with CRTOOLS_INIT_PID=$CRTOOLS_INIT_PID doesn't exist"
	exit 1
fi

NS_ENTER=/bin/nsenter
[ ! -x $NS_ENTER ] || NS_ENTER=/usr/bin/nsenter

if [ ! -x $NS_ENTER ]; then
	echo "$NS_ENTER binary not found"
	exit 2
fi

JOIN_CT="$NS_ENTER -t $CRTOOLS_INIT_PID -m -u -p -n"

BASENAME=/usr/bin/basename
READLINK=/bin/readlink
UMOUNT=/bin/umount
MOUNT=/bin/mount
RM=/bin/rm
SYSTEMCTL=/bin/systemctl
MKTEMP=/bin/mktemp

# Skip container, if it's not systemd based
[ "$($JOIN_CT "$BASENAME" -- "$($JOIN_CT "$READLINK" /proc/1/exe)")" == "systemd" ] || exit 0

AUTOFS_SERVICES="$($JOIN_CT $SYSTEMCTL --no-legend  -t automount \
	 --state=active list-units | awk '{ print $1 }')"

bindmount=""

function remove_bindmount {
	if [ -n "$bindmount" ]; then
		$JOIN_CT "$UMOUNT" "$bindmount"
		$JOIN_CT "$RM" -rf "$bindmount"
		bindmount=""
	fi
}
trap remove_bindmount EXIT

function get_fs_type {
	local mountpoint=$1

	local top_mount_id=""
	local top_mount_fs_type=""

	while IFS='' read -r line; do
		# Skip those entries which do not match the mountpoint
		[ "$(echo "$line" | awk '{print $5;}')" = "$mountpoint" ] || continue

		local mnt_id
		mnt_id=$(echo "$line" | awk '{print $1;}')
		local mnt_parent_id
		mnt_parent_id=$(echo "$line" | awk '{print $2;}')
		local mnt_fs_type
		mnt_fs_type=$(echo "$line" | sed 's/.* - //g' | awk '{print $1;}')

		# Skip mount entry, if not the first one and not a child
		[ -n "$top_mount_id" ] && [ "$mnt_parent_id" != "$top_mount_id" ] && continue

		top_mount_id=$mnt_id
		top_mount_fs_type=$mnt_fs_type
	done < "/proc/$CRTOOLS_INIT_PID/mountinfo"

	if [ -z "$top_mount_fs_type" ]; then
		echo "Failed to find $mountpoint mountpoint"
		return 1
	fi

	echo "$top_mount_fs_type"
	return 0
}

function bind_mount {
	local from=$1
	local to=$2

	$JOIN_CT "$MOUNT" --bind "$from" "$to" && return 0

	echo "Failed to bind mount $from to $to"
	return 1
}

function save_mountpoint {
	local mountpoint=$1
	local top_mount_fs_type=""

	if ! top_mount_fs_type=$(get_fs_type "$mountpoint"); then
		echo "$top_mount_fs_type"
		return
	fi

	# Nothing to do, if no file system is on top of autofs
	[ "$top_mount_fs_type" = "autofs" ] && return

	bindmount=$($JOIN_CT "$MKTEMP" -d)
	if [ -z "$bindmount" ]; then
		echo "Failed to create temporary directory"
		return 1
	fi

	# No need to unmount fs on top of autofs:
	# systemd will does it for us on service restart
	bind_mount "$mountpoint" "$bindmount" || $JOIN_CT "$RM" -rf "$bindmount"
}

function restore_mountpoint {
	local mountpoint=$1

	[ -n "$bindmount" ] || return

	# Umount file system, remounted by systemd, if any
	if ! top_mount_fs_type=$(get_fs_type "$mountpoint"); then
		echo "$top_mount_fs_type"
		return
	fi

	# Nothing to do, if no file system is on top of autofs
	if [ "$top_mount_fs_type" != "autofs" ]; then
		$JOIN_CT umount "$mountpoint" || echo "Failed to umount $mountpoint"
	fi

	# Restore origin file system even if we failed to unmount the new one
	bind_mount "$bindmount" "$mountpoint"
	remove_bindmount
}

function restart_service {
	local service=$1
	local mountpoint
	if mountpoint=$($JOIN_CT "$SYSTEMCTL" show "$service" -p Where | sed 's/.*=//g'); then
		echo "Failed to get mountpoint for $service service"
		return 1
	fi

	if [ -z "$mountpoint" ]; then
		echo "$service service mountpoint string is empty"
		return 1
	fi

	# Try to move restored bind-mount aside and exit if Failed
	# Nothing to do, if we Failed
	save_mountpoint "$mountpoint" || return

	if ! $JOIN_CT "$SYSTEMCTL" restart "$service"; then
		echo "Failed to restart $service service"
		return
	fi
	echo "$service restarted"

	# Try to move saved monutpoint back on top of autofs
	restore_mountpoint "$mountpoint"
}

function skip_service {
	local service=$1
	local mountpoint
	local top_mount_fs_type

	mountpoint=$($JOIN_CT "$SYSTEMCTL" show "$service" -p Where | sed 's/.*=//g')

	if [ -z "$mountpoint" ]; then
		echo "Failed to discover $service mountpoint"
		return 1
	fi

	top_mount_fs_type=$(get_fs_type "$mountpoint")
	# This is SPFS mount point in "Stub" mode. It can't be moved.
	if [ "$top_mount_fs_type" == "fuse.spfs" ]; then
		echo "spfs mount"
		return 1
	fi

	return 0
}

for service in $AUTOFS_SERVICES; do
	if ! skip_message=$(skip_service "$service"); then
		echo "$service skipped ($skip_message)"
	else
		restart_service "$service"
	fi
done

exit 0
