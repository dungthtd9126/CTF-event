FROM ubuntu AS builder
RUN apt update && apt install -y expect

FROM pwn.red/jail:0.3.0
COPY --from=builder / /srv
COPY greetings /srv/app/greetings
COPY libc.so.6 /srv/app/libc.so.6
COPY ld-linux-x86-64.so.2 /srv/app/ld-linux-x86-64.so.2
COPY run.sh /srv/app/run
COPY flag.txt /srv/flag.txt
RUN chmod +x /srv/app/run /srv/app/greetings /srv/app/ld-linux-x86-64.so.2
ENV JAIL_TMP_SIZE=100M
ENV JAIL_MEM=64M
ENV JAIL_CPU=1000
ENV JAIL_TIME=120
