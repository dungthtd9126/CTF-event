FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /challenge
COPY tcache_stash_revenge run.sh flag.example  ./
RUN chmod +x tcache_stash_revenge run.sh
EXPOSE 41052
CMD ["socat", "-T", "60", "TCP-LISTEN:41052,reuseaddr,fork", "EXEC:./run.sh,stderr"]
