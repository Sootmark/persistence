#!/bin/sh
# Copy a Debian 13 (trixie) system's default persistence files into a
# folder, for tests/debian.rs (SOOTMARK_PERSISTENCE_DEBIAN=<folder>).
# Most are GPL-licensed, so they're fetched, never vendored.
#
#   tests/debian/fetch.sh <folder>
#
# Needs docker. The files land below <folder> at their host paths, with
# the package versions in <folder>/versions.txt.
set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <folder>" >&2
    exit 2
fi
mkdir -p "$1"
out=$(cd "$1" && pwd)

docker run --rm -v "$out:/out" -e OWNER="$(id -u):$(id -g)" debian:trixie sh -euc '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        cron anacron sudo openssh-server logrotate e2fsprogs sysstat login udev kmod >/dev/null
    cd /
    for file in \
        etc/crontab etc/cron.d/anacron etc/cron.d/e2scrub_all etc/cron.d/sysstat \
        etc/anacrontab etc/sudoers etc/sudoers.d/README \
        etc/profile etc/bash.bashrc etc/skel/.bashrc etc/skel/.profile \
        usr/lib/systemd/system/anacron.service usr/lib/systemd/system/anacron.timer \
        usr/lib/systemd/system/apt-daily.timer usr/lib/systemd/system/cron.service \
        usr/lib/systemd/system/e2scrub_all.timer usr/lib/systemd/system/logrotate.service \
        usr/lib/systemd/system/logrotate.timer usr/lib/systemd/system/ssh.service \
        usr/lib/systemd/system/ssh.socket usr/lib/systemd/system/sysstat-collect.timer \
        etc/init.d/cron etc/init.d/ssh etc/init.d/sudo etc/ssh/sshd_config \
        etc/pam.d/common-auth etc/pam.d/common-account etc/pam.d/common-password \
        etc/pam.d/common-session etc/pam.d/sshd etc/pam.d/su etc/pam.d/sudo \
        etc/pam.d/login etc/pam.d/cron etc/pam.d/other \
        usr/lib/udev/rules.d/50-udev-default.rules usr/lib/udev/rules.d/60-persistent-storage.rules \
        usr/lib/udev/rules.d/80-drivers.rules usr/lib/udev/rules.d/99-systemd.rules \
        usr/lib/modprobe.d/aliases.conf usr/lib/modprobe.d/fbdev-blacklist.conf \
        usr/lib/modprobe.d/systemd.conf etc/modules-load.d/modules.conf
    do
        mkdir -p "/out/$(dirname "$file")"
        cp "$file" "/out/$file"
    done
    dpkg-query -W cron anacron sudo openssh-server logrotate e2fsprogs sysstat \
        bash base-files apt login libpam-runtime udev kmod >/out/versions.txt
    chown -R "$OWNER" /out
'
echo "Debian files in $out"
