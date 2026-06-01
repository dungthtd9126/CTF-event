FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    clang-18 \
    lld-18 \
    llvm-18 \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# rustc 1.82
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain 1.82.0 --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY Cargo.toml build.rs ./
COPY src/ src/
COPY csrc/ csrc/

ENV CC=clang-18
ENV CXX=clang++-18
ENV RUSTFLAGS="-C linker=clang-18 -C link-arg=-fuse-ld=lld-18"

RUN cargo build --release 2>&1 && \
    strip /build/target/release/secureboard

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/sh -d /app ctf

WORKDIR /app

COPY --from=builder /build/target/release/secureboard /usr/local/bin/secureboard
COPY flag.txt /flag.txt

RUN chmod 755 /usr/local/bin/secureboard \
    && chmod 444 /flag.txt

RUN cp /lib/x86_64-linux-gnu/libc.so.6 /app/libc.so.6

USER ctf
EXPOSE 8080

CMD ["/bin/sh", "-c", "while true; do /usr/local/bin/secureboard; done"]
