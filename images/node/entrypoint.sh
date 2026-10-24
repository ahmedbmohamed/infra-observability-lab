#!/bin/sh
set -eu

if [ -z "${AUTHORIZED_KEY:-}" ]; then
  echo "AUTHORIZED_KEY is not set: nobody could log in." >&2
  exit 1
fi

install -d -m 0700 -o ops -g ops /home/ops/.ssh
printf '%s\n' "$AUTHORIZED_KEY" > /home/ops/.ssh/authorized_keys
chown ops:ops /home/ops/.ssh/authorized_keys
chmod 0600 /home/ops/.ssh/authorized_keys

ssh-keygen -A >/dev/null
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
