FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    xinetd \
    zlib1g \
    libbz2-1.0 \
    liblzma5 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

COPY deploy/prob /home/ctf/prob
COPY deploy/run.sh /home/ctf/run.sh
COPY deploy/flag /home/ctf/flag
COPY xinetd.conf /etc/xinetd.d/afterimage

RUN chmod 755 /home/ctf/prob /home/ctf/run.sh \
    && chmod 440 /home/ctf/flag \
    && chown -R root:ctf /home/ctf

EXPOSE 10039

CMD ["/usr/sbin/xinetd", "-dontfork"]

