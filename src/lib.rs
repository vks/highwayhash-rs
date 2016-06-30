#![feature(test)]
extern crate core;
extern crate test;


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

#[derive(Clone, Debug)]
/// std-Wrapper for `highway_tree_hash`.
pub struct HighwayHasher {
    key: [u64; 4],
    hash: u64,
}

impl HighwayHasher {
    fn new() -> HighwayHasher {
        HighwayHasher {
            key: [0, 0, 0, 0],
            hash: 0,
        }
    }

    fn new_with_key(key: [u64; 4]) -> HighwayHasher {
        HighwayHasher {
            key: key,
            hash: 0,
        }
    }
}

impl core::default::Default for HighwayHasher {
    fn default() -> Self {
        HighwayHasher::new()
    }
}

impl core::hash::Hasher for HighwayHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, msg: &[u8]) {
        let lhs = self.hash;
        let rhs = highway_tree_hash(&self.key, msg);
        // Ideally we want to use the hash function to combine with the old value.
        // This is however not possible without allocation with the current interface. So we use a
        // way to combine hashes proposed in
        // https://stackoverflow.com/questions/5889238/why-is-xor-the-default-way-to-combine-hashes
        self.hash ^= rhs.wrapping_add(0x9e3779b97f4a7c16)
                        .wrapping_add(lhs << 6)
                        .wrapping_add(lhs >> 2);
    }
}

#[cfg(test)]
mod test_highway {
    use super::*;

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
}


#[cfg(test)]
mod test_std {
    use core::hash::{Hash, Hasher};
    use test::{Bencher, black_box};
    use super::HighwayHasher;

    fn hash<T: Hash>(x: &T) -> u64 {
        let mut st = HighwayHasher::new();
        x.hash(&mut st);
        st.finish()
    }

    fn hash_with_keys<T: Hash>(k1: u64, k2: u64, x: &T) -> u64 {
        let mut st = HighwayHasher::new_with_key([k1, k2, 0, 0]);
        x.hash(&mut st);
        st.finish()
    }

    fn hash_bytes(x: &[u8]) -> u64 {
        let mut s = HighwayHasher::default();
        Hasher::write(&mut s, x);
        s.finish()
    }

    #[test] #[cfg(target_arch = "arm")]
    fn test_hash_usize() {
        let val = 0xdeadbeef_deadbeef_u64;
        assert!(hash(&(val as u64)) != hash(&(val as usize)));
        assert_eq!(hash(&(val as u32)), hash(&(val as usize)));
    }
    #[test] #[cfg(target_arch = "x86_64")]
    fn test_hash_usize() {
        let val = 0xdeadbeef_deadbeef_u64;
        assert_eq!(hash(&(val as u64)), hash(&(val as usize)));
        assert!(hash(&(val as u32)) != hash(&(val as usize)));
    }
    #[test] #[cfg(target_arch = "x86")]
    fn test_hash_usize() {
        let val = 0xdeadbeef_deadbeef_u64;
        assert!(hash(&(val as u64)) != hash(&(val as usize)));
        assert_eq!(hash(&(val as u32)), hash(&(val as usize)));
    }

    #[test]
    fn test_hash_idempotent() {
        let val64 = 0xdeadbeef_deadbeef_u64;
        assert_eq!(hash(&val64), hash(&val64));
        let val32 = 0xdeadbeef_u32;
        assert_eq!(hash(&val32), hash(&val32));
    }

    #[test]
    fn test_hash_no_bytes_dropped_64() {
        let val = 0xdeadbeef_deadbeef_u64;

        assert!(hash(&val) != hash(&zero_byte(val, 0)));
        assert!(hash(&val) != hash(&zero_byte(val, 1)));
        assert!(hash(&val) != hash(&zero_byte(val, 2)));
        assert!(hash(&val) != hash(&zero_byte(val, 3)));
        assert!(hash(&val) != hash(&zero_byte(val, 4)));
        assert!(hash(&val) != hash(&zero_byte(val, 5)));
        assert!(hash(&val) != hash(&zero_byte(val, 6)));
        assert!(hash(&val) != hash(&zero_byte(val, 7)));

        fn zero_byte(val: u64, byte: usize) -> u64 {
            assert!(byte < 8);
            val & !(0xff << (byte * 8))
        }
    }

    #[test]
    fn test_hash_no_bytes_dropped_32() {
        let val = 0xdeadbeef_u32;

        assert!(hash(&val) != hash(&zero_byte(val, 0)));
        assert!(hash(&val) != hash(&zero_byte(val, 1)));
        assert!(hash(&val) != hash(&zero_byte(val, 2)));
        assert!(hash(&val) != hash(&zero_byte(val, 3)));

        fn zero_byte(val: u32, byte: usize) -> u32 {
            assert!(byte < 4);
            val & !(0xff << (byte * 8))
        }
    }

    #[test]
    fn test_hash_no_concat_alias() {
        let s = ("aa", "bb");
        let t = ("aabb", "");
        let u = ("a", "abb");

        assert!(s != t && t != u);
        assert!(hash(&s) != hash(&t) && hash(&s) != hash(&u));

        let u = [1, 0, 0, 0];
        let v = (&u[..1], &u[1..3], &u[3..]);
        let w = (&u[..], &u[4..4], &u[4..4]);

        assert!(v != w);
        assert!(hash(&v) != hash(&w));
    }

    #[bench]
    fn bench_str_under_8_bytes(b: &mut Bencher) {
        let s = "foo";
        b.iter(|| {
            assert_eq!(hash(&s), 15154260541782849163);
        })
    }

    #[bench]
    fn bench_str_of_8_bytes(b: &mut Bencher) {
        let s = "foobar78";
        b.iter(|| {
            assert_eq!(hash(&s), 143184826081496726);
        })
    }

    #[bench]
    fn bench_str_over_8_bytes(b: &mut Bencher) {
        let s = "foobarbaz0";
        b.iter(|| {
            assert_eq!(hash(&s), 3189161910928201212);
        })
    }

    #[bench]
    fn bench_long_str(b: &mut Bencher) {
        let s = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor \
    incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud \
    exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute \
    irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla \
    pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui \
    officia deserunt mollit anim id est laborum.";
        b.iter(|| {
            assert_eq!(hash(&s), 7042102786451223823);
        })
    }

    #[bench]
    fn bench_u32(b: &mut Bencher) {
        let u = 162629500u32;
        let u = black_box(u);
        b.iter(|| {
            hash(&u)
        });
        b.bytes = 8;
    }

    #[bench]
    fn bench_u32_keyed(b: &mut Bencher) {
        let u = 162629500u32;
        let u = black_box(u);
        let k1 = black_box(0x1);
        let k2 = black_box(0x2);
        b.iter(|| {
            hash_with_keys(k1, k2, &u)
        });
        b.bytes = 8;
    }

    #[bench]
    fn bench_u64(b: &mut Bencher) {
        let u = 16262950014981195938u64;
        let u = black_box(u);
        b.iter(|| {
            hash(&u)
        });
        b.bytes = 8;
    }

    #[bench]
    fn bench_bytes_4(b: &mut Bencher) {
        let data = black_box([b' '; 4]);
        b.iter(|| {
            hash_bytes(&data)
        });
        b.bytes = 4;
    }

    #[bench]
    fn bench_bytes_7(b: &mut Bencher) {
        let data = black_box([b' '; 7]);
        b.iter(|| {
            hash_bytes(&data)
        });
        b.bytes = 7;
    }

    #[bench]
    fn bench_bytes_8(b: &mut Bencher) {
        let data = black_box([b' '; 8]);
        b.iter(|| {
            hash_bytes(&data)
        });
        b.bytes = 8;
    }

    #[bench]
    fn bench_bytes_a_16(b: &mut Bencher) {
        let data = black_box([b' '; 16]);
        b.iter(|| {
            hash_bytes(&data)
        });
        b.bytes = 16;
    }

    #[bench]
    fn bench_bytes_b_32(b: &mut Bencher) {
        let data = black_box([b' '; 32]);
        b.iter(|| {
            hash_bytes(&data)
        });
        b.bytes = 32;
    }

    #[bench]
    fn bench_bytes_c_128(b: &mut Bencher) {
        let data = black_box([b' '; 128]);
        b.iter(|| {
            hash_bytes(&data)
        });
        b.bytes = 128;
    }
}
