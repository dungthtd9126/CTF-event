FROM ubuntu:24.04 AS app

FROM pwn.red/jail
COPY --from=app / /srv
RUN mkdir /srv/app
COPY bytecrusher /srv/app/run
COPY flag.txt /srv/app
RUN chmod 755 /srv/app/run
RUN chmod 644 /srv/app/flag.txt

ENV JAIL_POW=30000
