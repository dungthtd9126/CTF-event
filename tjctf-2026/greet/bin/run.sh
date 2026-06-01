#!/bin/sh
stdbuf -o0 /app/ld-linux-x86-64.so.2 --library-path /app /app/greetings
