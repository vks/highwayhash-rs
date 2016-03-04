extern "C" {
    fn _Z15HighwayTreeHashRA4_KmPKhm(key: *const u64, bytes: *const u8, size: u64) -> u64;
    fn _Z11SipTreeHashRA4_KmPKhm(key: *const u64, bytes: *const u8, size: u64) -> u64;
    fn _Z7SipHashPKmPKhm(key: *const u64, bytes: *const u8, size: u64) -> u64;
}



fn highway_tree_hash(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        _Z15HighwayTreeHashRA4_KmPKhm(key.as_ptr(), bytes.as_ptr(),
                                      bytes.len() as u64)
    }
}

fn sip_tree_hash(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        _Z11SipTreeHashRA4_KmPKhm(key.as_ptr(), bytes.as_ptr(),
                                  bytes.len() as u64)
    }
}

fn sip_hash(key: &[u64; 2], bytes: &[u8]) -> u64 {
    unsafe {
        _Z7SipHashPKmPKhm(key.as_ptr(), bytes.as_ptr(), bytes.len() as u64)
    }
}

#[test]
fn test_highway_tree_hash() {
    let key = [1, 2, 3, 4];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(highway_tree_hash(&key, &bytes), 2515751569969494610);
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
fn test_sip_hash() {
    let key = [1, 2];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(sip_hash(&key, &bytes), 16073328535944263387);
    // TODO: Verify this is the correct value.
}

