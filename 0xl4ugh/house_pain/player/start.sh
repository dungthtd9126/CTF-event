#!/bin/bash
set -e

IMAGE_NAME=house-of-pain
CONTAINER_NAME=house-of-pain-ctf
PORT=1337

# Stop and remove old container if exists
docker rm -f $CONTAINER_NAME 2>/dev/null || true

# Build image
docker build -t $IMAGE_NAME .

# Run challenge
docker run -d \
  --name $CONTAINER_NAME \
  -p $PORT:1337 \
  --restart unless-stopped \
  $IMAGE_NAME

echo "[+] Challenge running on localhost:$PORT"
