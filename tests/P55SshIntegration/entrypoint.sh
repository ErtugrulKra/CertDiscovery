#!/bin/sh
set -eu
cp /integration/authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
ssh-keygen -A
/usr/sbin/sshd
if command -v nginx >/dev/null 2>&1; then
  exec nginx -g 'daemon off;'
fi
exec apachectl -D FOREGROUND
