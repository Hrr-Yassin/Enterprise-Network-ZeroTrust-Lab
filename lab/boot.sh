#!/bin/busybox sh
set -eu
export PATH=/bin:/usr/bin:/sbin
export PYTHONPATH=/ztlab
export PYTHONDONTWRITEBYTECODE=1
export PYTHON_COLORS=0
export OPENSSL_CONF=/etc/ssl/openssl.cnf
umask 022

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755 tmpfs /run
mount -t tmpfs -o mode=1777 tmpfs /tmp
mkdir -p /dev/shm /dev/pts /run/netns /run/ztlab
mount -t tmpfs -o mode=1777 tmpfs /dev/shm
mount -t devpts devpts /dev/pts
printf 'ZTLAB BOOT %s\n' "$(cat /proc/cmdline)"
printf 1 > /run/ztlab/guest

if ! /usr/bin/python3 -m lab.runtime; then
    printf 'ZTLAB guest deployment exited with an error\n'
fi
case "$(cat /proc/cmdline)" in
    *ztlab.mode=live*)
        printf '\nLab guest console. Shut down with poweroff -f.\n'
        setsid cttyhack sh -i
        ;;
esac
poweroff -f
