#!/bin/bash

# Match the docker group GID to the mounted docker.sock's GID
SOCK_GID=$(stat -c '%g' /var/run/docker.sock)
if getent group docker >/dev/null 2>&1; then
    groupmod -g "$SOCK_GID" docker
else
    groupadd -g "$SOCK_GID" docker
fi
usermod -aG docker ctf

# Save environment variables for SSH sessions
echo "CTFD_INSTANCES='${CTFD_INSTANCES}'" > /etc/spawn.env

# Build inner challenge image using host Docker
echo "Building inner challenge image..."
docker build -t old-days-inner -f /Dockerfile.inner /challenge
echo "Inner image built."

# Start SSH server in foreground
exec /usr/sbin/sshd -D -e
