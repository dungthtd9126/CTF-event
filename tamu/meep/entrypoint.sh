#!/bin/sh

if [ "$DEBUG" = "1" ]; then
    echo "[*] Running in DEBUG mode | Debug port at 1234"
    echo "Use gdb to connect to the process by running 'target remote localhost:1234' from gdb (or gdb-multiarch)"
    exec qemu-mips-static -g 1234 ./meep
else
    echo "[*] Running in normal mode"
    exec qemu-mips-static ./meep
fi