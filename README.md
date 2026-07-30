# Zend X Chain — devnet

Código fuente de la capa de consenso, red P2P y wallet de **Zend X
Chain**, la blockchain propia (PoW abierta + UTXO) detrás de ZNX. Este repo
es un espejo público de la carpeta `blockchain/` del monorepo interno de
ZendX — sin nada del resto de la plataforma (que sí es privada).

**Esto es el devnet**: sin premine, sin fondos con valor real, dificultad
pensada para poder minar con hardware normal. El objetivo es técnico y de
comunidad — auditar el código de consenso y correr un nodo de verdad. El
mainnet real (con sus propios parámetros, todavía en preparación) va a ser
una red separada.

- [`docs/MINING.md`](docs/MINING.md) — cómo correr tu propio nodo y minar.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — diseño técnico (crates,
  formato de transacción/bloque, storage).
- [`docs/CONSENSUS.md`](docs/CONSENSUS.md) — reglas de consenso (PoW,
  ajuste de dificultad, subsidio/halving).

## Estructura

```
crates/       - workspace de Rust (znx-node, znx-consensus, znx-p2p, znx-wallet, ...)
genesis/      - archivo de génesis del devnet
docs/         - documentación técnica
Dockerfile    - imagen para correr un nodo sin compilar
```

## Build local

```
cargo build --release -p znx-node -p znx-wallet-cli
```
