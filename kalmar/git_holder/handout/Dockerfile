FROM archlinux:latest

RUN pacman --noconfirm -Sy socat python3 git

RUN mkdir /app
COPY clone.py /app/clone.py
COPY ./flag.txt /app/flag.txt
RUN useradd -m -k user:user user
USER user
WORKDIR /tmp

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 /app/clone.py",stderr
