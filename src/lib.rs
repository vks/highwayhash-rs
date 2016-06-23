extern "C" {
    fn SipHashC(key: *const u64, bytes: *const u8, size: u64) -> u64;

    fn SipTreeHashC(key: *const u64, bytes: *const u8, size: u64) -> u64;
    fn ScalarSipTreeHashC(key: *const u64, bytes: *const u8, size: u64) -> u64;

    fn ScalarHighwayTreeHashC(key: *const u64, bytes: *const u8, size: u64) -> u64;
    fn SSE41HighwayTreeHashC(key: *const u64, bytes: *const u8, size: u64) -> u64;
    fn HighwayTreeHashC(key: *const u64, bytes: *const u8, size: u64) -> u64;
}

/// J-lanes tree hash based upon multiplication and "zipper merges".
///
/// Robust versus timing attacks because memory accesses are sequential
/// and the algorithm is branch-free. Scalar implementation.
///
/// `key` is a secret 256-bit key unknown to attackers.
/// `bytes` is the data to hash (possibly unaligned).
///
/// Returns a 64-bit hash of the given data bytes.
pub fn highway_tree_hash_scalar(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        ScalarHighwayTreeHashC(key.as_ptr(), bytes.as_ptr(),
                               bytes.len() as u64)
    }
}

/// J-lanes tree hash based upon multiplication and "zipper merges".
///
/// Robust versus timing attacks because memory accesses are sequential
/// and the algorithm is branch-free. Requires an AVX-2 capable CPU.
///
/// `key` is a secret 256-bit key unknown to attackers.
/// `bytes` is the data to hash (possibly unaligned).
///
/// Returns a 64-bit hash of the given data bytes.
pub fn highway_tree_hash(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        HighwayTreeHashC(key.as_ptr(), bytes.as_ptr(),
                         bytes.len() as u64)
    }
}

/// Fast, cryptographically strong pseudo-random function. Useful for:
///
/// * hash tables holding attacker-controlled data. This function is
///   immune to hash flooding DOS attacks because multi-collisions are
///   infeasible to compute, provided the key remains secret.
/// * deterministic/idempotent 'random' number generation, e.g. for
///   choosing a subset of items based on their contents.
///
/// Robust versus timing attacks because memory accesses are sequential
/// and the algorithm is branch-free. Compute time is proportional to the
/// number of 8-byte packets and 1.5x faster than an sse41 implementation.
/// Requires an AVX-2 capable CPU.
///
/// `key` is a secret 256-bit key unknown to attackers.
/// `bytes` is the data to hash (possibly unaligned).
///
/// Returns a 64-bit hash of the given data bytes.
pub fn sip_tree_hash(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        SipTreeHashC(key.as_ptr(), bytes.as_ptr(),
                     bytes.len() as u64)
    }
}

/// Fast, cryptographically strong pseudo-random function. Useful for:
///
/// * hash tables holding attacker-controlled data. This function is
///   immune to hash flooding DOS attacks because multi-collisions are
///   infeasible to compute, provided the key remains secret.
/// * deterministic/idempotent 'random' number generation, e.g. for
///   choosing a subset of items based on their contents.
///
/// Robust versus timing attacks because memory accesses are sequential
/// and the algorithm is branch-free. Compute time is proportional to the
/// number of 8-byte packets. This version does not use SIMD.
///
/// `key` is a secret 256-bit key unknown to attackers.
/// `bytes` is the data to hash (possibly unaligned).
///
/// Returns a 64-bit hash of the given data bytes.
pub fn sip_tree_hash_scalar(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        ScalarSipTreeHashC(key.as_ptr(), bytes.as_ptr(),
                           bytes.len() as u64)
    }
}

/// Fast, cryptographically strong pseudo-random function. Useful for:
///
/// * hash tables holding attacker-controlled data. This function is
///   immune to hash flooding DOS attacks because multi-collisions are
///   infeasible to compute, provided the key remains secret.
/// * deterministic/idempotent 'random' number generation, e.g. for
///   choosing a subset of items based on their contents.
///
/// Robust versus timing attacks because memory accesses are sequential
/// and the algorithm is branch-free. Compute time is proportional to the
/// number of 8-byte packets and 1.5x faster than an sse41 implementation.
/// Requires an AVX-2 capable CPU.
///
/// `key` is a secret 128-bit key unknown to attackers.
/// `bytes` is the data to hash; `ceil(size / 8) * 8` bytes are read.
///
/// Returns a 64-bit hash of the given data bytes.
pub fn sip_hash(key: &[u64; 2], bytes: &[u8]) -> u64 {
    unsafe {
        SipHashC(key.as_ptr(), bytes.as_ptr(), bytes.len() as u64)
    }
}

/// J-lanes tree hash based upon multiplication and "zipper merges".
///
/// Robust versus timing attacks because memory accesses are sequential
/// and the algorithm is branch-free. Requires an SSE4.1 capable CPU.
///
/// `key` is a secret 256-bit key unknown to attackers.
/// `bytes` is the data to hash (possibly unaligned).
///
/// Returns a 64-bit hash of the given data bytes.
pub fn highway_tree_hash_sse41(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        SSE41HighwayTreeHashC(key.as_ptr(), bytes.as_ptr(),
                                      bytes.len() as u64)
    }
}

#[test]
fn test_highway_tree_hash() {
    let key = [1, 2, 3, 4];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(highway_tree_hash(&key, &bytes), 12047785261820867033);
    // TODO: Verify this is the correct value.
}

#[test]
fn test_highway_tree_hash_scalar() {
    let key = [1, 2, 3, 4];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(highway_tree_hash_scalar(&key, &bytes), 12047785261820867033);
    // TODO: Verify this is the correct value.
}

#[test]
fn test_highway_tree_hash_sse41() {
    let key = [1, 2, 3, 4];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(highway_tree_hash_sse41(&key, &bytes), 12047785261820867033);
    // TODO: Verify this is the correct value.
}

#[test]
fn test_sip_tree_hash() {
    let key = [1, 2, 3, 4];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(sip_tree_hash(&key, &bytes), 10345371778616741034);
    // TODO: Verify this is the correct value.
}

#[test]
fn test_sip_tree_hash_scalar() {
    let key = [1, 2, 3, 4];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(sip_tree_hash_scalar(&key, &bytes), 10345371778616741034);
    // TODO: Verify this is the correct value.
}

#[test]
fn test_sip_hash() {
    let key = [1, 2];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(sip_hash(&key, &bytes), 16073328535944263387);
    // TODO: Verify this is the correct value.
}
