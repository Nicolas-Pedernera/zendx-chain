# Zend X Chain — devnet

Source code for the consensus layer, P2P network, and wallet of **Zend X Chain**, the custom blockchain (open PoW + UTXO) behind ZNX. This repo is a public mirror of the `blockchain/` folder from ZendX's internal monorepo — nothing else from the rest of the platform is included (which remains private).

**This is the devnet**: no premine, no funds with real value, difficulty tuned so it can be mined with regular hardware. The goal is technical and community-driven — auditing the consensus code and running a real node. The actual mainnet (with its own parameters, still in preparation) will be a separate network.

- [`docs/MINING.md`](docs/MINING.md) — how to run your own node and mine.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — technical design (crates, transaction/block format, storage).
- [`docs/CONSENSUS.md`](docs/CONSENSUS.md) — consensus rules (PoW, difficulty adjustment, subsidy/halving).

## Structure

```text
crates/       - Rust workspace (znx-node, znx-consensus, znx-p2p, znx-wallet, ...)
genesis/      - devnet genesis file
docs/         - technical documentation
Dockerfile    - image to run a node without compiling
```

## Local build

```bash
cargo build --release -p znx-node -p znx-wallet-cli
```
