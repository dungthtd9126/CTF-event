FROM archlinux:latest

RUN pacman -Sy --noconfirm archlinux-keyring && \
    pacman -Syu --noconfirm && \
    pacman -S --noconfirm socat coreutils libseccomp

RUN useradd -m pwn
WORKDIR /home/pwn

COPY chall .
COPY flag.txt .

RUN chown -R pwn:pwn /home/pwn && \
    chmod 550 chall && \
    chmod 440 flag.txt

USER pwn
EXPOSE 1337

CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:timeout 60 ./chall,stderr"]
