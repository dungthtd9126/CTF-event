import sys

def rescue_astronaut(filepath):
    print(f"Reading transmissions from {filepath}...")
    try:
        # Read the file with utf-8 encoding to preserve the invisible characters
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Could not find '{filepath}'. Make sure it's in the same folder!")
        return

    binary_string = ""
    
    # Extract the binary bits based on the zero-width characters
    for char in content:
        if char == '\u200b':    # Zero-Width Space (ZWSP) -> 0
            binary_string += '0'
        elif char == '\u200c':  # Zero-Width Non-Joiner (ZWNJ) -> 1
            binary_string += '1'

    if not binary_string:
        print("No zero-width characters found! The transmission might be corrupted.")
        return

    # Group the binary string into chunks of 8 to form ASCII characters
    secret_message = ""
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            secret_message += chr(int(byte, 2))

    print("\n--- DECODED SOS MESSAGE (FLAG) ---")
    print(secret_message)
    print("----------------------------------")

if __name__ == "__main__":
    # Pointing directly to the recovered file
    rescue_astronaut('sos_message.txt')