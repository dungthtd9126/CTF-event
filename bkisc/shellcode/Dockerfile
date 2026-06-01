FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libseccomp2 \
        socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/chal

COPY chall /opt/chal/chall
COPY docker/entrypoint.sh /opt/chal/entrypoint.sh

RUN chmod 0555 /opt/chal/chall /opt/chal/entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/opt/chal/entrypoint.sh"]
