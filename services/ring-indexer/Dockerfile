FROM rust:1.98.1-slim-bookworm@sha256:ebd900bae66fd508b466cef82d64a83a5fb34682e4c8b2797a42908bddc95a57 AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# The repository root context resolves workspace path dependencies and the lockfile.
COPY . .

RUN cargo build --locked --release -p ring-indexer --bin ring-indexer

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10003 ring-indexer \
    && useradd --system --uid 10003 --gid ring-indexer \
        --home-dir /var/lib/ring-indexer --create-home ring-indexer

COPY --from=builder --chmod=0755 /workspace/target/release/ring-indexer /usr/local/bin/ring-indexer
COPY zolana/LICENSE zolana/THIRD_PARTY_NOTICES /usr/share/licenses/zolana/

LABEL org.opencontainers.image.title="Zolana Ring Indexer" \
      org.opencontainers.image.description="Zolana custom ring indexer beside Photon" \
      org.opencontainers.image.source="https://github.com/helius-labs/zolana-custom-rings" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV HOME=/var/lib/ring-indexer \
    RING_INDEXER_BIND=0.0.0.0
WORKDIR /var/lib/ring-indexer
USER ring-indexer

EXPOSE 8786
STOPSIGNAL SIGINT
ENTRYPOINT ["ring-indexer"]
