#!/bin/sh
cd "$(dirname "$0")"
cp -f flag.example flag.txt 2>/dev/null || true
exec ./blackglass_sandbox
