#!/usr/bin/env python3
from collections import defaultdict
import os
import signal
import socket
import time

HOST = "0.0.0.0"
PORT = 8000
RUNNER = "./runner"


hist = []

def allow_request():
    now = time.time()

    # Allow if no request in the last minute, or if fewer than
    # 10 requests in the last 10 minutes
    while hist and hist[0] < now - 600:
        hist.pop(0)

    if not hist or hist[-1] < now - 60 or len(hist) < 10:
        hist.append(now)
        return True
    return False


def handle_client(conn, addr):
    allowed = allow_request()

    pid = os.fork()
    if pid == 0:
        if not allowed:
            try:
                conn.sendall(b"rate limit exceeded\n")
                conn.close()
            except OSError:
                pass
            os._exit(1)

        fd = conn.fileno()
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        # restore default signal dispositions, not that it actually matters
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        os.execv(RUNNER, [RUNNER])
    else:
        conn.close()


def main():
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()

        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
