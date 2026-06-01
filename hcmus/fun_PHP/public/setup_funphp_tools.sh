#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="${1:-$HOME/ctf-tools/php-filters}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

echo "[*] cloning/updating tools into: $TOOLS_DIR"

if [ ! -d php_filter_chain_generator ]; then
  git clone https://github.com/synacktiv/php_filter_chain_generator.git
else
  git -C php_filter_chain_generator pull --ff-only || true
fi

if [ ! -d wrapwrap ]; then
  git clone https://github.com/ambionics/wrapwrap.git
else
  git -C wrapwrap pull --ff-only || true
fi

echo
echo "[*] verifying Synacktiv tool"
"$PYTHON_BIN" php_filter_chain_generator/php_filter_chain_generator.py --help || true

echo
echo "[*] verifying wrapwrap tool"
"$PYTHON_BIN" wrapwrap/wrapwrap.py --help || true

cat <<'EOF'

[+] done

Use with the unlock script like this:

python3 solve_funphp_filter_unlock.py http://chall.blackpinker.com:20180 \
  --pfcg "$HOME/ctf-tools/php-filters/php_filter_chain_generator/php_filter_chain_generator.py"

or:

python3 solve_funphp_filter_unlock.py http://chall.blackpinker.com:20180 \
  --wrapwrap "$HOME/ctf-tools/php-filters/wrapwrap/wrapwrap.py"

Tip:
- php_filter_chain_generator is the basic chain generator.
- wrapwrap is usually the more relevant one when you need exact wrapping/prefix-suffix behavior.

EOF
