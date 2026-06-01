FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

RUN apt-get update && apt-get install -y socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash pwn

WORKDIR /home/pwn

COPY ./dead_pixel ./dead_pixel
COPY ./flag       ./flag

RUN chown root:pwn ./dead_pixel ./flag \
 && chmod 750 ./dead_pixel \
 && chmod 440 ./flag

USER pwn

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./dead_pixel,stderr"]
