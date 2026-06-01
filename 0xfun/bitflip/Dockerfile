FROM ubuntu:24.04

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -m pwn

WORKDIR /srv/app

COPY main run
COPY commands flag libc.so.6 ld-linux-x86-64.so.2 ./

RUN chown -R root:root /srv \
 && chmod 555 /srv \
 && chmod 555 /srv/app \
 && chmod 555 /srv/app/run \
 && chmod 444 /srv/app/flag

USER pwn

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/srv/app/run,stderr"]
