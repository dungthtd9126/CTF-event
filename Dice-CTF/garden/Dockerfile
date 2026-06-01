FROM ubuntu:24.04 AS app

FROM pwn.red/jail
COPY --from=app / /srv
RUN mkdir /srv/app
COPY garden /srv/app/run
COPY ld-linux-x86-64.so.2 /srv/app
COPY libc.so.6 /srv/app
COPY flag.txt /srv/app
RUN chmod 755 /srv/app/run
RUN chmod 755 /srv/app/ld-linux-x86-64.so.2
RUN chmod 755 /srv/app/libc.so.6
RUN chmod 644 /srv/app/flag.txt

ENV JAIL_POW=30000
