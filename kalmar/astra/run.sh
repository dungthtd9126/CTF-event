#!/bin/sh

exploit=$(mktemp)
cp "${1:-/dev/null}" "$exploit"
[ $(stat -c%s "$exploit") -lt 4096 ] && truncate -s 4096 "$exploit"

trap 'rm -f "$exploit"' EXIT INT TERM

qemu-system-x86_64 \
    -M q35 \
    -m 256M \
    -smp cpus=1 \
    -cpu qemu64,+smep -enable-kvm \
    -cdrom challenge.iso -boot dc \
    -drive file="$exploit",format=raw,read-only,if=none,id=nvme \
    -device virtio-blk,serial=deadc0ff,drive=nvme \
    -nographic -monitor none

