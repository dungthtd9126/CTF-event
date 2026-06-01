#!/bin/sh

if [ "$(uname -m)" = "aarch64" ]; then
    runner="./military-system"
else
    runner="qemu-aarch64-static ./military-system"
fi

if [ "$DEBUG" = "1" ]; then
    if [ "$runner" = "./military-system" ]; then
        echo "[*] DEBUG requested, but no native gdbstub is available in this image"
        echo "[*] Running the binary directly instead"
        exec socat TCP-LISTEN:9001,reuseaddr,fork EXEC:"./military-system",stderr
    fi

    echo "[*] Running in DEBUG mode | Debug port at 1234"
    echo "Use host GDB to connect: 'target remote 127.0.0.1:1234'"
    exec socat TCP-LISTEN:9001,reuseaddr,fork EXEC:"qemu-aarch64-static -g 1234 ./military-system",stderr
else
    echo "[*] Running in normal mode"
    exec socat TCP-LISTEN:9001,reuseaddr,fork EXEC:"$runner",stderr
fi
