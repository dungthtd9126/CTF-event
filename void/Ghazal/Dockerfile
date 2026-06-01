FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /challenge
COPY no_eyes run.sh flag.example libc.so.6 ld-linux-x86-64.so.2 ./
RUN chmod +x no_eyes run.sh
EXPOSE 41051
CMD ["socat", "-T", "60", "TCP-LISTEN:41051,reuseaddr,fork", "EXEC:./run.sh,stderr"]
