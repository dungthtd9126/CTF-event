# ═══════════════════════════════════════════════════════════════════
#  Havok's Cosmic Rings — Local Testing Container
#  Lets you run the challenge exactly as it runs on the real server.
#
#  Build & run:
#    docker build -t havok-local .
#    docker run -it --rm -p 1337:1337 havok-local
#
#  Then in another terminal:
#    python3 solve.py REMOTE HOST=localhost PORT=1337
# ═══════════════════════════════════════════════════════════════════
FROM ubuntu:22.04

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        socat libseccomp2 && \
    rm -rf /var/lib/apt/lists/*

# Create user and write run.sh BEFORE stripping binaries
RUN useradd --no-create-home --uid 1337 --shell /usr/sbin/nologin ctf && \
    mkdir -p /lib/challenge /home/ctf && \
    printf '#!/bin/sh\nexec /lib/challenge/ld-linux-x86-64.so.2 --library-path /lib/challenge /home/ctf/havok\n' \
        > /home/ctf/run.sh && \
    chown root:ctf /home/ctf/run.sh && \
    chmod 550 /home/ctf/run.sh

# Dummy flag — the real server has the actual flag
COPY --chown=root:ctf --chmod=440 flag.txt /flag.txt

COPY --chown=root:ctf --chmod=550 havok               /home/ctf/havok
COPY --chmod=755       libc.so.6                       /lib/challenge/libc.so.6
COPY --chmod=755       ld-linux-x86-64.so.2            /lib/challenge/ld-linux-x86-64.so.2

EXPOSE 1337
USER ctf
CMD ["socat", "-T120", \
     "TCP-LISTEN:1337,reuseaddr,fork,max-children=50", \
     "EXEC:/home/ctf/run.sh,stderr"]
