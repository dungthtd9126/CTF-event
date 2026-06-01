from pwn import *
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES

# Connection details
HOST = 'dora-nulls.ctf.prgy.in'
PORT = 1337

def solve():
    # Use ssl context for --ssl
    r = remote(HOST, PORT, ssl=True)

    def login(username, challenge, response):
        r.sendlineafter(b"choose ", b"1")
        r.sendlineafter(b"challenge (hex): ", challenge.hex().encode())
        r.sendlineafter(b"username: ", username.encode())
        line = r.recvline().decode()
        if "server challenge" not in line:
            return None
        server_chal = bytes.fromhex(line.split(": ")[1].strip())
        r.sendlineafter(b"response (hex): ", response.hex().encode())
        return server_chal, r.recvline().decode()

    # 1. Register a controlled user to understand the math
    my_user = "attacker123"
    my_secret = "0" * 64
    r.sendlineafter(b"choose ", b"2")
    r.sendlineafter(b"username: ", my_user.encode())
    r.sendlineafter(b"password hash (64 chars): ", my_secret.encode())

    # 2. Extract the expected path logic
    # We can't easily spoof the Admin without the secret, 
    # but the verify_credential function is vulnerable to a 
    # statistical attack or a specific property if we can find a collision.
    
    # In this specific challenge, since we can't control the Admin secret,
    # and the mask is based on a HMAC of the session key, we brute-force
    # the 1-byte XOR checksum (1/256 chance).
    
    print("[*] Attempting XOR checksum bypass on Administrator...")
    
    challenge = os.urandom(8)
    fake_response = b"\x00" * 8 # We just need the XOR sum to hit 0
    
    for i in range(500): # 0x1337 attempts allowed in main()
        if i % 10 == 0: print(f"[*] Attempt {i}...")
        
        server_chal, result = login("Administrator", challenge, fake_response)
        
        if "authentication successful" in result:
            print("[+] Success!")
            print(r.recvline().decode()) # This should be the flag
            break
    
    r.close()

if __name__ == "__main__":
    solve()