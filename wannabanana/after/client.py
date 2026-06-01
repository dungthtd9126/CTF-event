#!/usr/bin/env python3
import argparse
import base64
import re
import socket
import subprocess
import sys
from pathlib import Path


MENU_MARKER = b"0. exit\n"
BASE64_INPUT = b"base64 input:\n"
BASE64_OUTPUT_RE = re.compile(br"base64 output:\n([A-Za-z0-9+/=]+)\n")


class Channel:
    def __init__(self, proc=None, sock=None):
        self.proc = proc
        self.sock = sock

    def close(self):
        if self.sock is not None:
            self.sock.close()
        if self.proc is not None:
            try:
                self.proc.terminate()
            except ProcessLookupError:
                pass

    def send(self, data):
        if self.sock is not None:
            self.sock.sendall(data)
            return
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def sendline(self, data):
        self.send(data + b"\n")

    def recv_one(self):
        if self.sock is not None:
            data = self.sock.recv(1)
            if not data:
                raise EOFError("connection closed")
            return data
        data = self.proc.stdout.read(1)
        if not data:
            raise EOFError("process closed")
        return data

    def read_until(self, marker):
        buf = bytearray()
        while not bytes(buf).endswith(marker):
            buf += self.recv_one()
        return bytes(buf)


def open_channel(args):
    if args.host:
        port = args.port or 10039
        return Channel(sock=socket.create_connection((args.host, port), timeout=10))

    binary = Path(args.binary or Path(__file__).resolve().parent / "deploy" / "prob")
    proc = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    return Channel(proc=proc)


def prompt_choice():
    print("1. upload")
    print("2. download")
    print("3. exit")
    return input("> ").strip()


def upload(ch):
    path = Path(input("file path: ").strip())
    data = path.read_bytes()
    ch.sendline(b"1")
    ch.read_until(BASE64_INPUT)
    ch.sendline(base64.b64encode(data))
    response = ch.read_until(MENU_MARKER)
    if b"upload ok" in response:
        print("upload ok")
    else:
        sys.stdout.buffer.write(response)


def download(ch):
    out = input("output path [preview.png]: ").strip() or "preview.png"
    ch.sendline(b"2")
    response = ch.read_until(MENU_MARKER)
    match = BASE64_OUTPUT_RE.search(response)
    if not match:
        sys.stdout.buffer.write(response)
        return
    data = base64.b64decode(match.group(1))
    Path(out).write_bytes(data)
    print(f"saved {out} ({len(data)} bytes)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="remote host")
    parser.add_argument("--port", type=int, help="remote port")
    parser.add_argument("--binary", help="local challenge binary")
    args = parser.parse_args()

    ch = open_channel(args)
    try:
        ch.read_until(MENU_MARKER)
        while True:
            choice = prompt_choice()
            if choice == "1":
                upload(ch)
            elif choice == "2":
                download(ch)
            elif choice == "3":
                ch.sendline(b"0")
                break
            else:
                print("invalid choice")
    finally:
        ch.close()


if __name__ == "__main__":
    main()
