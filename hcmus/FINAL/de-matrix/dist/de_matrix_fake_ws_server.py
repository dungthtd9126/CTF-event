#!/usr/bin/env python3
import argparse, base64, hashlib, socket, struct, threading
GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

def recv_exact(c,n):
    data=b''
    while len(data)<n:
        chunk=c.recv(n-len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_frame(c):
    h = recv_exact(c,2)
    if not h:
        return None
    b1,b2 = h
    opcode = b1 & 0x0f
    masked = (b2 >> 7) & 1
    ln = b2 & 0x7f
    if ln == 126:
        ext = recv_exact(c,2)
        if not ext: return None
        ln = struct.unpack('!H', ext)[0]
    elif ln == 127:
        ext = recv_exact(c,8)
        if not ext: return None
        ln = struct.unpack('!Q', ext)[0]
    mask = recv_exact(c,4) if masked else b''
    payload = recv_exact(c,ln) if ln else b''
    if payload is None:
        return None
    if masked:
        payload = bytes(b ^ mask[i % 4] for i,b in enumerate(payload))
    return opcode, payload

def send_frame(c, opcode, payload=b''):
    ln = len(payload)
    if ln < 126:
        hdr = bytes([0x80 | opcode, ln])
    elif ln < 65536:
        hdr = bytes([0x80 | opcode, 126]) + struct.pack('!H', ln)
    else:
        hdr = bytes([0x80 | opcode, 127]) + struct.pack('!Q', ln)
    c.sendall(hdr + payload)

def send_text(c, text):
    send_frame(c, 1, text.encode())

def handle(conn, addr, reply):
    req = b''
    while b'\r\n\r\n' not in req:
        chunk = conn.recv(4096)
        if not chunk:
            conn.close(); return
        req += chunk
    key = None
    for line in req.decode('latin1', 'ignore').split('\r\n'):
        if line.lower().startswith('sec-websocket-key:'):
            key = line.split(':',1)[1].strip()
            break
    if not key:
        conn.close(); return
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    resp = (
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Accept: {accept}\r\n\r\n'
    ).encode()
    conn.sendall(resp)
    print(f'[+] client {addr[0]}:{addr[1]} connected', flush=True)
    try:
        while True:
            frame = recv_frame(conn)
            if frame is None:
                break
            opcode, payload = frame
            if opcode == 1:
                msg = payload.decode('utf-8', 'ignore')
                print(f'[>] {msg}', flush=True)
                send_text(conn, reply)
            elif opcode == 8:
                break
            elif opcode == 9:
                send_frame(conn, 0xA, payload)
    finally:
        conn.close()
        print(f'[-] client disconnected', flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=9001)
    ap.add_argument('--reply', default='Incorrect position')
    args = ap.parse_args()

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen(5)
    print(f'[*] listening on {args.host}:{args.port}', flush=True)
    while True:
        c,a = s.accept()
        threading.Thread(target=handle, args=(c,a,args.reply), daemon=True).start()

if __name__ == '__main__':
    main()
