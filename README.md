# XCA - Topological Data Analysis Cryptosystem

XCA (eXperimental Cryptographic Algorithm) is a novel encryption scheme based on Topological Data Analysis (TDA) and graph homomorphisms.

## Features

- **Graph-based encryption** using topological properties
- **IND-CPA security** through randomized padding
- **Zstd compression** for ciphertext size optimization
- **Flexible configuration** with unified API
- **Post-quantum resistance** (under analysis)

## Quick Start

```rust
use XCAlgo::tda::{tda_keygen, tda_encrypt, tda_decrypt};

// Generate keys
let (pk, sk) = tda_keygen(128, 192, 3.0)?;

// Encrypt message
let plaintext = b"Hello, XCA!";
let ciphertext = tda_encrypt(plaintext, &pk, &sk)?;

// Decrypt message
let decrypted = tda_decrypt(&ciphertext, &sk)?;
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
XCAlgo = "0.1.0"
```

## Security Features

### IND-CPA Security (Randomized Padding)

By default, XCA uses randomized padding to achieve IND-CPA security:

```rust
use XCAlgo::tda::{tda_encrypt_with_randomness, tda_decrypt_with_randomness};

let ciphertext = tda_encrypt_with_randomness(plaintext, &pk, &sk)?;
let decrypted = tda_decrypt_with_randomness(&ciphertext, &sk)?;
```

**Structure:** `[length: 4 bytes][nonce: 8 bytes][plaintext]`

### Compression Support

Reduce ciphertext size with Zstd compression:

```rust
use XCAlgo::tda::{tda_encrypt_randomized_compressed, tda_decrypt_decompressed_randomized};

// Encrypt with randomness + compression
let compressed_ct = tda_encrypt_randomized_compressed(plaintext, &pk, &sk)?;
let decrypted = tda_decrypt_decompressed_randomized(&compressed_ct, &sk)?;
```

## Performance

Benchmarked on modern hardware:

| Operation | Graph Size | Time |
|-----------|------------|------|
| KeyGen | 64 nodes | 622 µs |
| KeyGen | 128 nodes | 2.89 ms |
| KeyGen | 256 nodes | 13.66 ms |
| Encrypt | 16 bytes | 151 ns |
| Encrypt | 64 bytes | 326 ns |

**Ciphertext Expansion:** ~32x (without compression)

See [BENCHMARK.md](BENCHMARK.md) for detailed performance analysis.

## Documentation

- [BENCHMARK.md](BENCHMARK.md) - Performance benchmarks and comparisons
- [MATHEMATICAL_VERIFICATION.md](docs/MATHEMATICAL_VERIFICATION.md) - Formal verification
- [ADVANCED_SECURITY_ANALYSIS.md](ADVANCED_SECURITY_ANALYSIS.md) - Security analysis

## Security Considerations

⚠️ **Experimental**: XCA is a research project and has not undergone formal security audits.

- **Ciphertext expansion**: 32x without compression, ~26.7x with compression
- **Deterministic encryption**: Use randomized padding for IND-CPA security
- **Post-quantum security**: Under analysis (see ADVANCED_SECURITY_ANALYSIS.md)

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request.

## Citation

If you use XCA in your research, please cite:

```bibtex
@software{xca2026,
  title={XCA: Topological Data Analysis Cryptosystem},
  author={},
  year={2026},
  url={https://github.com/yourusername/XCAlgo}
}
```
