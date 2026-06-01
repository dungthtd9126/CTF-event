import bcrypt

# The hash you found in the source code
target_hash = b"$2a$04$MVbcnOnfWkUOv5qJYGcWy.NFbq6hWTvVoeOfH0nn4vpgglQu.ZwwC"

# A custom wordlist based on the "manosphere" hint
wordlist = [
    "alpha", "sigma", "matrix", "topg", "redpill", 
    "incel", "chad", "tate", "andrewtate", "based"
]

print("Starting brute force...")
for word in wordlist:
    # bcrypt.checkpw automatically handles the salt extraction and hashing
    if bcrypt.checkpw(word.encode('utf-8'), target_hash):
        print(f"[+] Match found! The access code is: {word}")
        break
else:
    print("[-] No match found in the custom list. Time for a bigger wordlist.")