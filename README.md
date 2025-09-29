# wasm-crypto

A WebAssembly library for post-quantum cryptography including ML-DSA (Module-Lattice-Based Digital Signature Algorithm) and ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism), as well as SHA-3 hashing.

## Features

- **ML-DSA-87**: Post-quantum digital signatures
- **ML-KEM-1024**: Post-quantum key encapsulation mechanism  
- **SHA-3-512**: Secure hash function

## Installation

```bash
npm install wasm-crypto
```

## Usage

```javascript
import init, { MlDsa, MlKem, sha3Hash512 } from 'wasm-crypto';

await init();

// Digital Signatures with ML-DSA
const mlDsa = new MlDsa();
const message = new Uint8Array([1, 2, 3, 4, 5]);
const signature = MlDsa.sign(mlDsa.signingKey, message);
const isValid = MlDsa.verify(message, signature, mlDsa.verifyingKey);

// Key Encapsulation with ML-KEM
const mlKem = new MlKem();
const encapsulation = MlKem.encapsulate(mlKem.encapsulationKey);
const sharedSecret = MlKem.decapsulate(mlKem.decapsulationKey, encapsulation.ciphertext);

// SHA-3 Hashing
const data = new Uint8Array([1, 2, 3, 4, 5]);
const hash = sha3Hash512(data);
```

## Publishing

This package is automatically published to npm when a new release is created on GitHub.

## License

MIT OR Apache-2.0