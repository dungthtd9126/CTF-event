from pwn import *
import pyte

# ---------------------------------------------------------
# 1. Setup Pyte Terminal Emulator
# ---------------------------------------------------------
# Set this to the dimensions your ncurses binary expects
# 80x24 is standard, but you may need to increase it if the game clips.
COLS, LINES = 120, 40 
screen = pyte.Screen(COLS, LINES)
stream = pyte.Stream(screen)

# ---------------------------------------------------------
# 2. Setup Pwntools Connection
# ---------------------------------------------------------
# IMPORTANT: You must use PTY (or your socat trick) so ncurses 
# actually outputs the formatted screen data instead of failing.
env = os.environ.copy()
env['TERM'] = 'xterm-256color'
p = process('./bmb', env=env, stdin=process.PTY, stdout=process.PTY)
# Or: p = remote('127.0.0.1', 1337)

# ---------------------------------------------------------
# 3. Helper Functions
# ---------------------------------------------------------
def sync_screen(timeout=0.5):
    """
    Reads all available raw bytes from pwntools and feeds them into the 
    pyte terminal emulator to update the visual 2D array.
    """
    try:
        # Read raw ncurses escape sequences
        raw_data = p.recv(timeout=timeout)
        if raw_data:
            # Pyte expects strings, not bytes. Use errors='ignore' so 
            # random binary leaks don't crash the utf-8 decoder!
            text_data = raw_data.decode('utf-8', errors='ignore')
            stream.feed(text_data)
    except EOFError:
        pass

def print_screen():
    """Prints the current terminal screen exactly as a human sees it."""
    print("+" + "-" * COLS + "+")
    for row in screen.display:
        print(f"|{row}|")
    print("+" + "-" * COLS + "+")

def get_line(row_index):
    """Returns a specific row from the screen as a string."""
    return screen.display[row_index]

# ---------------------------------------------------------
# 4. Exploit & Parsing Logic
# ---------------------------------------------------------

# Let the initial menu render
sync_screen(timeout=1.0)

# Optional: Print the screen to see what line your leak is on
# print_screen()

# Send whatever payload triggers your leak
# p.send(b's') # e.g., move down
# p.send(b'\n')
# sync_screen()

# --- THE PARSING ---
# Let's assume your leak prints on the 5th line down (index 4),
# and the text says: "Leaked Address: 0x7ffff7a...      "

target_row = get_line(4) 
print(f"[*] Raw Row 4: {target_row.strip()}")

if "0x" in target_row:
    # Use standard Python string parsing now that the ANSI codes are gone!
    leak_str = target_row.split("0x")[1].split()[0] # Grabs the hex part
    leak_int = int(leak_str, 16)
    
    log.success(f"Perfect Leak Extracted: {hex(leak_int)}")

p.interactive()
