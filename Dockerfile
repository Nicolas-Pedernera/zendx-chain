# Imagen pública para operadores externos de znx-node (Zend X Chain
# devnet — ver docs/MINING.md). A diferencia de Dockerfile (el que usa el
# deploy interno en Render para znx-node + znx-custody), esta imagen:
#   - Solo compila znx-node (nada de znx-custody, que no le sirve a un
#     operador externo y no tiene sentido publicar).
#   - No copia ningún keystore — un operador externo genera su propia
#     dirección con znx-wallet-cli keygen y la pasa por --miner-address.
#   - Es la imagen que se publica en un registry público (ver
#     docs/MINING.md) para no obligar a cada minero a compilar Rust desde
#     cero (build pesado: rocksdb-sys, libp2p-*).

FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --jobs 4 -p znx-node -p znx-wallet-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /home/znx znx
COPY --from=builder /build/target/release/znx-node /usr/local/bin/znx-node
COPY --from=builder /build/target/release/znx-wallet-cli /usr/local/bin/znx-wallet-cli
COPY genesis /genesis
RUN mkdir -p /data && chown znx:znx /data
USER znx
WORKDIR /data
EXPOSE 26656 26657
ENTRYPOINT ["znx-node"]
CMD ["--data-dir", "/data", "--genesis", "/genesis/devnet.json"]
