FROM rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        openssh-client \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/data /workspace

COPY --from=builder /src/target/release/pc /usr/local/bin/pc
COPY docker-entrypoint.sh /usr/local/bin/pc-entrypoint
RUN chmod 0755 /usr/local/bin/pc-entrypoint

WORKDIR /app

ENV PC_LISTEN=0.0.0.0:8686
ENV PC_HOME=/app/data
ENV PC_WORKSPACE=/workspace
ENV PC_SECURITY_MODE=full
ENV PC_SECURITY_NETWORK=true
ENV PC_SECURITY_PROTECT_SECRETS=true

EXPOSE 8686

VOLUME ["/app/data", "/workspace"]

ENTRYPOINT ["/usr/local/bin/pc-entrypoint"]
