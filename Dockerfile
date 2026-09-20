FROM rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
        ca-certificates \\
        curl \\
        git \\
        openssh-client \\
    && rm -rf /var/lib/apt/lists/* \\
    && mkdir -p /app/data /workspace

COPY --from=builder /src/target/release/pc /usr/local/bin/pc

WORKDIR /app

ENV PC_LISTEN=0.0.0.0:8787
ENV PC_DATABASE_URL=sqlite:///app/data/pc.db?mode=rwc
ENV PC_WORKSPACE=/workspace

EXPOSE 8787

VOLUME ["/app/data", "/workspace"]

ENTRYPOINT ["pc"]
