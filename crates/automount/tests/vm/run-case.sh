#!/bin/sh
# 20261127 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261127 - Time-limit the final tree listing so a dead daemon cannot hang a run - Claude - scottfk
# 20261127 - Add restartd: kill the daemon with SIGKILL and start it again over its mounts - Claude - scottfk
# 20261127 - A case with a net file gets a network namespace and fake NFS servers (net-setup.sh) - Claude - scottfk
# 20261127 - UTS namespace with the case's NIS domain (domain file); var/ laid over /var - Claude - scottfk
#
# run-case.sh - run one daemon case on the root test VM (see tests/common/vm.rs)
#
# Usage: run-case.sh IMPL CASEDIR
#
# IMPL is c (the reference build in $B/c) or r (the Rust automount in $B/r).
# CASEDIR holds etc/ (files laid over /etc), args (the daemon's arguments, one
# per line) and steps (a shell fragment run while the daemon runs). The case
# runs in a private mount namespace: /etc and /usr are overlays, /run, /mnt
# and /tmp are tmpfs, so nothing it does outlives it. mount and umount are
# recorders that log to out/cmds and run the real programs (NFS mounts become
# tmpfs mounts). A domain file sets the NIS domain (in a UTS namespace of the
# case's own) and var/ is laid over /var. Outputs go to CASEDIR/out.
set -eu
IMPL=$1
C=$2
B=$(cd "$(dirname "$0")" && pwd)
rm -rf "$C/out"
mkdir -p "$C/out" "$C/ovl"
[ -x "$B/real-mount" ] || cp /usr/bin/mount "$B/real-mount"
[ -x "$B/real-umount" ] || cp /usr/bin/umount "$B/real-umount"
NETNS=
[ -f "$C/net" ] && NETNS=-n
exec unshare -m -u $NETNS --propagation private sh -eu -c '
B=$1; C=$2; IMPL=$3
mount -t tmpfs tmpfs "$C/ovl"
mkdir -p "$C/ovl/eu" "$C/ovl/ew" "$C/ovl/uu" "$C/ovl/uw" "$C/ovl/srv"
mount -t overlay overlay -o lowerdir=/etc,upperdir="$C/ovl/eu",workdir="$C/ovl/ew" /etc
mount -t overlay overlay -o lowerdir=/usr,upperdir="$C/ovl/uu",workdir="$C/ovl/uw" /usr
for d in /run /mnt /tmp; do mount -t tmpfs tmpfs $d; done
if [ -d "$C/var" ]; then
	mkdir -p "$C/ovl/vu" "$C/ovl/vw"
	mount -t overlay overlay -o lowerdir=/var,upperdir="$C/ovl/vu",workdir="$C/ovl/vw" /var
	cp -a "$C/var/." /var/
fi
if [ -f "$C/domain" ]; then cat "$C/domain" > /proc/sys/kernel/domainname; else echo "(none)" > /proc/sys/kernel/domainname; fi
rm -rf /etc/autofs /etc/conf.d/autofs /etc/auto.master
mkdir -p /etc/autofs
[ -d "$C/etc" ] && cp -a "$C/etc/." /etc/
# The host clock may be ahead, and maps newer than the map read look changed.
[ -d "$C/etc" ] && (cd "$C/etc" && find . -type f) | while read -r f; do touch -d "1 hour ago" "/etc/$f"; done
if [ "$IMPL" = c ]; then
	mkdir -p /usr/lib64/autofs
	cp "$B"/c/modules/*.so /usr/lib64/autofs/
	cp "$B/c/lib/libautofs.so" /usr/lib64/
	(cd /usr/lib64/autofs && ln -s lookup_file.so lookup_files.so && ln -s lookup_yp.so lookup_nis.so &&
		ln -s mount_ext2.so mount_ext3.so && ln -s mount_ext2.so mount_ext4.so && ln -s mount_nfs.so mount_nfs4.so)
	AUTOMOUNT=$B/c/daemon/automount
else
	rm -rf /usr/lib64/autofs
	AUTOMOUNT=$B/r/automount
fi
cat > /usr/bin/mount <<EOR
#!/bin/sh
echo mount "\$@" >> $C/out/cmds
case " \$* " in
*" -t nfs"*) n=\$#; eval last=\\\${\$n}; exec $B/real-mount -t tmpfs tmpfs "\$last" ;;
esac
exec $B/real-mount "\$@"
EOR
cat > /usr/bin/umount <<EOR
#!/bin/sh
echo umount "\$@" >> $C/out/cmds
exec $B/real-umount "\$@"
EOR
chmod 755 /usr/bin/mount /usr/bin/umount
: > "$C/out/cmds"
SRV=$C/ovl/srv
export SRV
[ -f "$C/net" ] && . "$B/net-setup.sh"
[ -f "$C/pre" ] && . "$C/pre"
# The daemon, in its own session: processes in its group see the raw mounts.
set --
[ -f "$C/args" ] && while IFS= read -r a; do set -- "$@" "$a"; done < "$C/args"
setsid "$AUTOMOUNT" "$@" > "$C/out/log" 2>&1 &
PID=$!
LOG=$C/out/log
export AUTOMOUNT
snap() { grep -E " /mnt" /proc/mounts | sed -E "s/(fd|pgrp|pipe_ino)=[0-9]+/\1=N/g" | sort >> "$C/out/steps"; echo -- >> "$C/out/steps"; }
note() { echo "$*" >> "$C/out/steps"; }
waitlog() { n=0; while ! grep -q -- "$1" "$LOG" 2>/dev/null; do n=$((n+1)); [ $n -gt ${2:-100} ] && { note "timeout waiting for $1"; return 1; }; kill -0 $PID 2>/dev/null || { [ -n "${3:-}" ] || note "daemon exited waiting for $1"; return 1; }; sleep 0.1; done; }
ready() { waitlog "${1:-ghosting enabled}" 100; }
sig() { kill -"$1" $PID; }
trig() { timeout 20 ls "$1" >/dev/null 2>&1; note "trig $1: $?"; }
quiet() { sleep "${1:-1}"; }
restartd() { kill -KILL $PID; wait $PID 2>/dev/null; note "restarted"; set --; [ -f "$C/args" ] && while IFS= read -r a; do set -- "$@" "$a"; done < "$C/args"; setsid "$AUTOMOUNT" "$@" >> "$C/out/log" 2>&1 & PID=$!; }
stopd() { kill -TERM $PID 2>/dev/null || true; n=0; while kill -0 $PID 2>/dev/null; do n=$((n+1)); [ $n -gt 300 ] && { note "daemon did not stop"; kill -KILL $PID; break; }; sleep 0.1; done; }
: > "$C/out/steps"
set +e
[ -f "$C/steps" ] && . "$C/steps"
stopd
wait $PID
echo "exit $?" > "$C/out/status"
grep -E " /mnt" /proc/mounts | sed -E "s/(fd|pgrp|pipe_ino)=[0-9]+/\1=N/g" | sort > "$C/out/mounts-after"
timeout 20 find /mnt /run | sort > "$C/out/tree-after"
command -v net_down >/dev/null && net_down
' run-case "$B" "$C" "$IMPL"
