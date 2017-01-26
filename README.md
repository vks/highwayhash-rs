# highwayhash-rs

Rust Bindings to AVX2-optimized SIP-like hash functions. This crate offers
bindings to three hash functions implemented in C++
[here](https://github.com/google/highwayhash):

- `siphash`: A portable implementation of the SIP hash function, that is about
  2 times faster than the [reference
  implementation](https://github.com/floodyberry/supercop/blob/master/crypto_auth/siphash24/sse41/siphash.c).
- `siphash13`: A faster but weaker variant of `siphash`.
- `highwayhash64`: A new hash that mixes the inputs using AVX2 instructions.
  It is about 5 times faster than `siphash`. A preliminary cryptanalysis is
  given [here](https://arxiv.org/abs/1612.06257).

For `highwayhash64` there are three implementations: one using AVX2, another one using SSE4.1 and a third one that is portable by not relying on specific instruction sets. To profit from the faster implementations, make sure to enable the instruction sets at compile time using `RUSTFLAGS="-C target-cpu=native"` or similar.

## Status

The bindings are in an early state. They currently should work on Unix, but are
only tested on Linux. `make` and a C++ compiler are required to build the underlying C++ library. A nightly Rust compiler is required.
