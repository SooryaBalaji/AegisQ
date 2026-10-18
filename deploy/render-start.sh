#!/bin/sh
set -e
mkdir -p "$AEGISQ_HOME"
if [ "$(id -u)" = "0" ]; then
  chown -R aegisq:aegisq "$AEGISQ_HOME"
  exec setpriv --reuid=aegisq --regid=aegisq --init-groups "$@"
fi
exec "$@"
