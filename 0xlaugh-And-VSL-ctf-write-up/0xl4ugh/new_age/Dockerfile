FROM python:3.9-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY new_age .

RUN useradd -m ctf
USER ctf
COPY flag_name_Should_Be_R@ndom_ahahahahahahahahah.txt .

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/new_age"

