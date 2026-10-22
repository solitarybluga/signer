ARG RUST_IMAGE=rust:1.90-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder

WORKDIR /app

# Copy the whole workspace because Cargo resolves every workspace member.
# target/, data/, .git/ and local secrets are excluded by .dockerignore.
COPY . .

RUN cargo build --release --locked -p signer-server

FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system signer \
    && useradd --system --gid signer --home-dir /var/lib/signer --create-home signer

WORKDIR /app

COPY --from=builder /app/target/release/signer /usr/local/bin/signer
COPY docker/signer.toml /etc/signer/signer.toml

RUN mkdir -p /var/lib/signer/data \
    && chown -R signer:signer /var/lib/signer

USER signer

EXPOSE 50051

VOLUME ["/var/lib/signer/data"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/signer"]
CMD ["--config", "/etc/signer/signer.toml"]
