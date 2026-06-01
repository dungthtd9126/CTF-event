FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

RUN apt update
RUN apt-get install -y socat gdbserver

RUN useradd -m -s /bin/bash pwn

WORKDIR /home/pwn

COPY ./flag ./flag
COPY ./prob ./prob

RUN chmod 644 ./flag
RUN chmod 755 ./prob

USER pwn

EXPOSE 5000
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:./prob,stderr
