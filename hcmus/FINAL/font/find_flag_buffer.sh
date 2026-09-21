#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 /path/to/chall [payload_readonly.mdoc] [ld-linux-x86-64.so.2]" >&2
  exit 1
fi

CHALL=$1
PAYLOAD=${2:-payload_readonly.mdoc}
LOADER=${3:-}
DIR=$(cd "$(dirname "$CHALL")" && pwd)
CHALL_BASENAME=$(basename "$CHALL")
TRACE_SO="$DIR/trace_malloc.so"
TRACE_LOG="$DIR/trace_malloc.log"

cc -shared -fPIC -O0 -o "$TRACE_SO" /mnt/data/font_trace_malloc.c -ldl
python3 /mnt/data/font_solve_readonly.py -o "$DIR/$PAYLOAD" >/dev/null

pushd "$DIR" >/dev/null
if [[ -n "$LOADER" ]]; then
  LD_PRELOAD="$TRACE_SO" "$LOADER" --library-path "$DIR" "./$CHALL_BASENAME" "$PAYLOAD" >/dev/null 2> "$TRACE_LOG" || true
else
  LD_PRELOAD="$TRACE_SO" "./$CHALL_BASENAME" "$PAYLOAD" >/dev/null 2> "$TRACE_LOG" || true
fi
popd >/dev/null

BUF=$(python3 - "$TRACE_LOG" <<'PY'
import re, sys
seen = False
for line in open(sys.argv[1], 'r', errors='replace'):
    if 'fopen(flag.txt,rb)' in line:
        seen = True
        continue
    if seen and 'malloc(0x1000)=' in line:
        m = re.search(r'malloc\(0x1000\)=([^ ]+)', line)
        if m:
            print(m.group(1))
            raise SystemExit(0)
raise SystemExit(1)
PY
) || true

if [[ -z "$BUF" ]]; then
  echo "could not locate flag buffer; inspect $TRACE_LOG manually" >&2
  exit 2
fi

echo "$BUF"
