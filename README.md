![Continuous Integration](https://github.com/helium/helium-crypto-rs/workflows/Continuous%20Integration/badge.svg)
[![codecov](https://codecov.io/gh/helium/helium-crypto-rs/branch/main/graph/badge.svg?token=YA02M87E5B)](https://codecov.io/gh/helium/helium-crypto-rs)

## helium-crypto-rs

This library implements various cryptographic functions used by [Helium
Blockchain](https://helium.com). This includes creating keypairs for supported
key types signing messages and verifying messages with public keys. Public keys
support binary and B58 encode/decoding as used by the Helium blockchain.

See the library documentation for usage details.

## Using

Add a dependency to your projects `Cargo.toml`:

```rust
helium-crypto = "<version>"
```
