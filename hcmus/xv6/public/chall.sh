#!/bin/bash

set -e

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp "$SRC/mkfs" "$SRC/kernel" "$SRC/flag.txt" "$WORK/"
cp -r "$SRC/user" "$WORK/user"
cd "$WORK"

rm -f user/_init

cat <<GLHF
Send the byte length of your program on the first line, then the raw bytes
GLHF

read -r LEN
case "$LEN" in
	''|*[!0-9]*) echo "invalid length"; exit 1 ;;
esac
if [ "$LEN" -gt 8388608 ]; then
	LEN=8388608
fi

head -c "$LEN" > user/_init

./mkfs fs.img user/*

timeout 8s qemu-system-riscv64 \
    -machine virt \
    -bios none \
    -kernel kernel \
    -m 128M \
    -smp 1 \
    -nographic \
    -global virtio-mmio.force-legacy=false \
    -drive file=fs.img,if=none,format=raw,id=x0 \
    -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
    -device loader,file=flag.txt,addr=0x87fff000,force-raw=on
