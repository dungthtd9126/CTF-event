from pwn import *

context.log_level = "debug"
io = remote("streams.tamuctf.com", 443, ssl=True, sni="meep")
io.interactive(prompt="")