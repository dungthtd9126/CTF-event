#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"

export LD_LIBRARY_PATH="$PWD/libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec ./dead_pixel_patched "$@"
