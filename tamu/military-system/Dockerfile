FROM debian:bookworm-slim

ARG FLAG_FILE=flag.txt

RUN dpkg --add-architecture arm64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libc6:arm64 \
        libgcc-s1:arm64 \
        ncurses-bin \
        qemu-user-static \
        socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

COPY . /tmp/build-context

RUN set -eu; \
    if [ -f /tmp/build-context/pwn/military-system/military-system ]; then \
        src_dir=/tmp/build-context/pwn/military-system; \
    elif [ -f /tmp/build-context/military-system ]; then \
        src_dir=/tmp/build-context; \
    else \
        echo "military-system binary not found in build context" >&2; \
        exit 1; \
    fi; \
    cp "${src_dir}/military-system" /challenge/military-system; \
    cp "${src_dir}/entrypoint.sh" /challenge/entrypoint.sh; \
    cp "${src_dir}/${FLAG_FILE}" /flag.txt; \
    chmod 0555 /challenge/military-system /challenge/entrypoint.sh; \
    chmod 0444 /flag.txt; \
    mkdir -p /home/ctf; \
    chown -R nobody:nogroup /challenge /home/ctf; \
    rm -rf /tmp/build-context

ENV TERM=xterm

USER nobody:nogroup

EXPOSE 9001

ENTRYPOINT ["/challenge/entrypoint.sh"]
