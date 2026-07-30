# Minar en el devnet de Zend X Chain

Esto es el **devnet** de Zend X Chain — una red de prueba pública, sin
premine, sin fondos con valor real. El objetivo es técnico y de comunidad:
que cualquiera pueda correr un nodo, sincronizar, minar y ver la red
funcionar de verdad, mientras el mainnet real (con sus propios parámetros,
todavía no publicados) se prepara aparte con calma.

**Los ZNX de este devnet no valen nada.** Cuando exista un mainnet real, va
a ser una red nueva y separada — nada de lo que mines acá se traslada.

## 1. Generar tu propia dirección

No necesitás pedirle nada a nadie — generás tu propia clave localmente:

```
znx-wallet-cli keygen --out mi-clave.json
```

Te va a pedir que elijas una contraseña para cifrar el keystore
localmente, y va a imprimir tu dirección `znx1...` — es la que vas a pasar
en `--miner-address` para recibir la recompensa de los bloques que mines.
Guardá bien `mi-clave.json` y esa contraseña: son lo único que necesitás
para volver a acceder a esos fondos (si en algún momento hacés `send`
desde esa dirección).

## 2. Correr tu nodo

### Con Docker (recomendado)

```
docker run -d --name znx-node \
  -p 26656:26656 \
  -v znx-data:/data \
  <IMAGEN_PUBLICA> \
  --data-dir /data \
  --genesis /genesis/devnet.json \
  --peer /ip4/<IP_DEL_BOOTNODE_PUBLICO>/tcp/26656 \
  --miner-address znx1TU_DIRECCION_ACA
```

### Compilando desde el código fuente

El código completo del devnet (crates de consenso, P2P, wallet) es
público — podés revisarlo antes de correrlo en `<URL_DEL_REPO_ESPEJO>`.

```
cargo build --release -p znx-node -p znx-wallet-cli
./target/release/znx-node \
  --data-dir ./data \
  --genesis genesis/devnet.json \
  --peer /ip4/<IP_DEL_BOOTNODE_PUBLICO>/tcp/26656 \
  --miner-address znx1TU_DIRECCION_ACA
```

## 3. Confirmar que estás sincronizado

El nodo expone un JSON-RPC de solo consulta en el puerto 26657 (local, no
hace falta abrirlo a internet):

```
curl -s -X POST http://127.0.0.1:26657 \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_latest_height","params":{}}'
```

Comparás la altura (`height`) contra la de otros nodos de la red — si vas
subiendo y te acercás a la altura del resto, estás sincronizado.

## Notas técnicas

- No hay descubrimiento automático de peers (sin Kademlia DHT, a
  propósito) — el único punto de entrada a la red es el bootnode público
  de arriba. Tu nodo va a re-conectar automáticamente si se cae la
  conexión.
- `--miner-address` es opcional: si lo omitís, tu nodo solo valida y
  sincroniza (no compite por bloques) — sirve igual como nodo de
  respaldo/validación.
- Bloque cada ~15 segundos, dificultad ajustada cada 60 bloques — pensado
  para poder minar con hardware normal, sin necesidad de hardware
  especializado.
