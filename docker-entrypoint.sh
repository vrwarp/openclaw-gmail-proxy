#!/bin/sh
# Run the proxy as a host-provided user so locked-down bind mounts work.
#
# On a NAS (e.g. Synology) you typically create a dedicated `docker_user`, give
# ONLY that user read/write on the shared folder you bind-mount, and deny
# everyone else. For the container to write there it must run as that user's
# numeric id. Pass it in with PUID / PGID (LinuxServer.io convention):
#
#     environment:
#       PUID: "1026"   # `id docker_user` -> uid
#       PGID: "100"    # `id docker_user` -> gid
#     volumes:
#       - /volume1/docker/openclaw-gmail-proxy/data:/data
#
# Behaviour:
#   * Started as root (the default): point the built-in `appuser` account at
#     PUID/PGID (defaults 10001, matching prior images), fix ownership of the
#     data dir, then DROP privileges and exec the app as that unprivileged user.
#   * Started as non-root (Docker `--user` / compose `user:` already picked the
#     uid): PUID/PGID are ignored and the app runs as-is. In that mode you must
#     make the mounted paths writable by that uid yourself.
set -e

PUID="${PUID:-10001}"
PGID="${PGID:-10001}"

if [ "$(id -u)" = "0" ]; then
    # -o allows re-using an id/gid that already exists (e.g. gid 100 = "users").
    groupmod -o -g "$PGID" appuser 2>/dev/null || true
    usermod  -o -u "$PUID" -g "$PGID" appuser 2>/dev/null || true

    # Only the persisted data dir needs chowning here. The policy.yaml bind
    # mount is owned by the host user already, and /app code stays read-only.
    chown -R appuser:appuser /data 2>/dev/null || true

    exec gosu appuser "$@"
fi

exec "$@"
