# Dockerfile
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends socat gdb gdbserver libseccomp-dev \
 && rm -rf /var/lib/apt/lists/*


RUN useradd -m -u 3000 pwn
WORKDIR /home/pwn

# Copy challenge artifacts (loader+libc are REQUIRED here)
COPY --chown=pwn:pwn bitdebit²_patched ./bitdebit²_patched
COPY --chown=pwn:pwn flag ./flag
COPY --chown=pwn:pwn libc.so.6 ./libc.so.6
COPY --chown=pwn:pwn ld-2.39.so ./ld-2.39.so

RUN chmod 555 ./bitdebit²_patched \
 && chmod 444 ./flag && chmod 555 ./libc.so.6 && chmod 555 ./ld-2.39.so

USER pwn


EXPOSE 1337
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./bitdebit²_patched,stderr