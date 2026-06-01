FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    qemu-user-static \
    gdbserver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /home
COPY meep /home/meep

ARG FLAG_FILE=flag.txt
COPY ${FLAG_FILE} /home/flag.txt

# Copy  MIPS loader & libs into /lib
COPY lib-mips/* /lib/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1234 9001

# Run gdbserver via qemu-user-static
ENTRYPOINT ["/entrypoint.sh"]