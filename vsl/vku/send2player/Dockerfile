FROM ubuntu:24.04

RUN apt-get update && apt-get install -y socat gcc-multilib

RUN useradd -m ctf

WORKDIR /home/ctf

COPY vku .
COPY run.sh .
COPY flag.txt /flag.txt


RUN chmod +x vku run.sh
RUN chown -R root:ctf /home/ctf
RUN chmod 444 /flag.txt

USER ctf

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/ctf/run.sh,stderr