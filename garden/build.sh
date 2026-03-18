#!/bin/bash

gcc garden.c -o garden -Wall
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./garden
patchelf --set-rpath ./ ./garden
