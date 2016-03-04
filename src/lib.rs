extern "C" {
    fn _Z15HighwayTreeHashRA4_KmPKhm(key: *const u64, bytes: *const u8, size: u64) -> u64;
}

fn highway_tree_hash(key: &[u64; 4], bytes: &[u8]) -> u64 {
    unsafe {
        _Z15HighwayTreeHashRA4_KmPKhm(key.as_ptr(), bytes.as_ptr(),
                                      bytes.len() as u64)
    }
}

#[test]
fn test_highwaytreehash() {
    let key = [1, 2, 3, 4];
    let bytes = [12, 23, 234, 123, 123, 2, 4];
    assert_eq!(highway_tree_hash(&key, &bytes), 2515751569969494610);
    // TODO: Verify this is the correct value.
}
