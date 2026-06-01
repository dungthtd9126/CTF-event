FROM ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf

WORKDIR /ctf

# Copy only the final binary
COPY chall ./chall
COPY flag.txt .

RUN chown -R root:ctf /ctf && \
    chmod 750 chall && \
    chmod 440 flag.txt

# drop privileges
USER ctf

EXPOSE 1337

CMD ["socat", \
     "TCP-LISTEN:1337,reuseaddr,fork", \
     "EXEC:./chall,stderr"]
