#!/bin/sh


# Requires: qemu-system-x86_64, bzImage, initrd.cpio.gz
# Build modules: make KDIR=/path/to/linux-6.1/build  (in src/)
# Build initrd:  ./build_initramfs.sh                 (from dir with *.ko files)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec qemu-system-x86_64 \
    -kernel "$SCRIPT_DIR/bzImage" \
    -initrd "$SCRIPT_DIR/initrd.cpio.gz" \
    -append "console=ttyS0 oops=panic panic=-1 nokaslr pti=on" \
    -cpu qemu64,+smep,+smap \
    -m 1G \
    -smp 1 \
    -nographic \
    -no-reboot \
    -net user,hostfwd=udp:127.0.0.1:31337-:31337 \
    -net nic,model=e1000 \
    -snapshot \
    -gdb tcp:127.0.0.1:3636
