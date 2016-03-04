# highwayhash-rs

Rust Bindings to AVX-2-optimized SIP-like hash functions.  This crate offers
bindings to three hash functions implemented in C++
[here](https://github.com/google/highwayhash):

- `sip_hash`: An AVX-2 implementation of the SIP hash function, that is about
  1.5 times faster the the SSE4.1 [reference
  implementation](https://github.com/floodyberry/supercop/blob/master/crypto_auth/siphash24/sse41/siphash.c).
- `sip_tree_hash`: Partitions the input into interleaved streams and hashes them
  independently. Results are combined using the SIP hash function. This retains
  the security guarantees of SIP and gives another 3 times speedup.
- `highway_tree_hash`: A new way of mixing the inputs using AVX-2 instructions.
  The security guarantees are not well established, but this gives another 2-3
  times speedup, especially for smaller inputs.

## Status

The bindings are in a very early state. They currently only work on Linux.
[Bazel](http://bazel.io) is required to build the underlying C++ library. (All
this will hopefully be fixed soon.)
