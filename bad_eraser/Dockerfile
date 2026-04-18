# Deploy
FROM ubuntu:22.04

RUN apt update && apt install -y socat

RUN useradd -m -s /bin/bash ctf

WORKDIR /ctf

COPY bad_eraser .
COPY flag.txt .

RUN chmod 555 bad_eraser && \
    chmod 444 flag.txt && \
    chown -R root:root /ctf

USER ctf

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/ctf/bad_eraser,stderr"]