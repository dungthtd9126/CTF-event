FROM ubuntu:22.04

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        socat \
        libseccomp2 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --no-create-home --uid 1337 --shell /usr/sbin/nologin ctf && \
    mkdir -p /home/ctf && \
    printf '#!/bin/sh\nulimit -t 60\nulimit -v 262144\nulimit -c 0\nexec /home/ctf/abyss\n' \
        > /home/ctf/run.sh && \
    chown root:ctf /home/ctf/run.sh && \
    chmod 550 /home/ctf/run.sh

COPY --chown=root:ctf --chmod=440 flag.txt /flag.txt
COPY --chown=root:ctf --chmod=550 abyss /home/ctf/abyss

VOLUME ["/tmp"]
EXPOSE 1333

USER ctf
CMD ["socat", "-T120", \
     "TCP-LISTEN:1333,reuseaddr,fork,max-children=2250", \
     "EXEC:/home/ctf/run.sh,stderr"]
