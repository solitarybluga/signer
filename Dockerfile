ARG RUST_IMAGE=docker.m.daocloud.io/library/rust:1.90-bookworm
ARG RUNTIME_IMAGE=docker.m.daocloud.io/library/debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder

# Optional crates.io-compatible sparse index mirror for restricted networks,
# e.g. sparse+https://mirrors.ustc.edu.cn/crates.io-index/
ARG CARGO_REGISTRY_MIRROR=""

WORKDIR /app

# Copy the whole workspace because Cargo resolves every workspace member.
# target/, data/, .git/ and local secrets are excluded by .dockerignore.
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    if [ -n "$CARGO_REGISTRY_MIRROR" ]; then \
        printf '[source.crates-io]\nreplace-with = "mirror"\n[source.mirror]\nregistry = "%s"\n' \
            "$CARGO_REGISTRY_MIRROR" > /usr/local/cargo/config.toml; \
    fi \
    && cargo build --release --locked -p signer-server \
    && cp target/release/signer /usr/local/bin/signer

FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system signer \
    && useradd --system --gid signer --home-dir /var/lib/signer --create-home signer

WORKDIR /app

COPY --from=builder /usr/local/bin/signer /usr/local/bin/signer
COPY docker/signer.toml /etc/signer/signer.toml

RUN mkdir -p /var/lib/signer/data \
    && chown -R signer:signer /var/lib/signer

USER signer

EXPOSE 50051

VOLUME ["/var/lib/signer/data"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/signer"]
CMD ["--config", "/etc/signer/signer.toml"]
