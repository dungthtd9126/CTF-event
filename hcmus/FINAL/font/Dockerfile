FROM ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf \
    && mkdir -p /tmp/ctf \
    && chmod 1777 /tmp/ctf

WORKDIR /home/ctf

COPY --chown=ctf:ctf chall /home/ctf/chall
COPY --chown=ctf:ctf chall.sh /home/ctf/chall.sh
COPY --chown=ctf:ctf flag.txt /home/ctf/flag.txt

RUN chmod 755 /home/ctf/chall /home/ctf/chall.sh

USER ctf

EXPOSE 1338

CMD ["socat", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:/home/ctf/chall.sh,stderr"]