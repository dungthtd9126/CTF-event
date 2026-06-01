FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

ENV PORT=1338

RUN apt update -y && apt install -y openssh-server docker.io curl python3 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash ctf && echo 'ctf:ctf' | chpasswd && usermod -aG docker ctf

RUN mkdir /var/run/sshd
RUN sed -i "s/#Port 22/Port ${PORT}/" /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Force all SSH sessions to spawn an isolated container
RUN echo "Match User ctf" >> /etc/ssh/sshd_config && \
    echo "  ForceCommand /usr/local/bin/spawn.sh" >> /etc/ssh/sshd_config

COPY ./spawn.sh /usr/local/bin/spawn.sh
RUN chmod +x /usr/local/bin/spawn.sh

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE ${PORT}
ENTRYPOINT ["/entrypoint.sh"]
