FROM rust:1.88.0-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release

FROM debian:12.11-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && groupadd --gid 10001 engram \
    && useradd --uid 10001 --gid engram --no-create-home --shell /usr/sbin/nologin engram \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/engram-mcp /usr/local/bin/engram-mcp

USER engram:engram
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/engram-mcp"]
