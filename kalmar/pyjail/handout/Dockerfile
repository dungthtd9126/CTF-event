FROM archlinux:base-devel

# Update the system and install necessary packages then clean up package cache to reduce image size
RUN pacman --noconfirm -Syu && pacman -S --noconfirm sagemath socat
RUN pacman -Scc --noconfirm

# Set up working dir
WORKDIR /app
COPY chal.py .

# Put the flag with an unguessable name in the root dir
COPY flag.txt /flag.txt
RUN mv /flag.txt /flag-$(openssl rand -hex 16).txt

ENTRYPOINT socat tcp-l:2020,fork,reuseaddr EXEC:"python chal.py"
