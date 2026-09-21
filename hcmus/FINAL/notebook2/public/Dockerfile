FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

RUN useradd -m -s /bin/bash pwn

WORKDIR /home/pwn

COPY ./flag ./flag
COPY ./prob ./prob
COPY ./goodluck.bin ./goodluck.bin
COPY ./entrypoint.sh ./entrypoint.sh

RUN chmod 644 ./flag
RUN chmod 755 ./prob
RUN chmod 644 ./goodluck.bin
RUN chmod 755 ./entrypoint.sh
RUN chmod 755 /home/pwn

EXPOSE 5000
CMD ["./entrypoint.sh"]
