# --- STAGE 1: Builder ---
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y gcc

WORKDIR /build
COPY pwn2.c .

# BUILD SETTINGS:
# -no-pie: Fixed base address (0x400000)
# -fstack-protector-all: Canary ON
# -Wl,-z,relro: RELRO ON (Partial by default without '-z now')
RUN gcc pwn2.c -o pwn2 \
    -no-pie \
    -fstack-protector-all \
    -Wl,-z,relro \
    -D_FORTIFY_SOURCE=2

# --- STAGE 2: Runner ---
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /home/ctf

# Copy the binary from builder
COPY --from=builder /build/pwn2 .

# Copy your specific GLIBC 2.39
COPY libc.so.6 /lib/x86_64-linux-gnu/libc.so.6

COPY flag.txt .

RUN chown -R root:ctf /home/ctf && \
    chmod 750 /home/ctf/pwn2 && \
    chmod 440 /home/ctf/flag.txt

USER ctf
EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./pwn2,stderr"]