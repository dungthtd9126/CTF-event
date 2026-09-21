#!/usr/bin/env bash

set -e

echo "Enter URL to download your font file:"

IFS= read -r -n 200 url
echo

curl -s --connect-timeout 10 --max-time 30 -r 0-20971519 -o font "$url"

./chall font