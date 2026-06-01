FROM pwn.red/jail:0.3.0
COPY --from=ubuntu / /srv
COPY Ox78 /srv/app/Ox78
COPY libc.so.6 /srv/app/libc.so.6
COPY ld-linux-x86-64.so.2 /srv/app/ld-linux-x86-64.so.2
COPY run.sh /srv/app/run
COPY flag.txt /srv/app/flag.txt
RUN chmod +x /srv/app/run /srv/app/Ox78 /srv/app/ld-linux-x86-64.so.2
RUN echo "test file" > /srv/tmp/test.txt
