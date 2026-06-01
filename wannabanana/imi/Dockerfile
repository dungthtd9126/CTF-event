FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

ENV PROB_NAME immutable
ENV PORT 33201

RUN apt-get update
RUN apt-get install socat -y

RUN useradd --create-home --shell /bin/bash ctf

WORKDIR /home/ctf/

COPY ./deploy/${PROB_NAME} ./${PROB_NAME}
COPY ./deploy/run.sh ./run.sh
COPY ./deploy/flag ./flag

RUN chmod +x ./${PROB_NAME}
RUN chmod +x ./run.sh

RUN chown -R root:ctf /home/ctf
RUN chmod -R 750 /home/ctf
RUN chmod 444 /home/ctf/flag

EXPOSE ${PORT}
CMD socat TCP-LISTEN:${PORT},reuseaddr,fork EXEC:./run.sh,stderr
