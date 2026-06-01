FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /challenge
COPY blackglass_sandbox run.sh flag.example  ./
RUN chmod +x blackglass_sandbox run.sh
EXPOSE 41053
CMD ["socat", "-T", "60", "TCP-LISTEN:41053,reuseaddr,fork", "EXEC:./run.sh,stderr"]
