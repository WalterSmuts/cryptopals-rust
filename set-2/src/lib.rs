pub fn pad_pkcs_7(mut input: Vec<u8>, block_size: usize) -> Vec<u8> {
    let num_pad_bytes = block_size - (input.len() % block_size);
    input.append(&mut vec![num_pad_bytes as u8; num_pad_bytes]);
    input
}

#[test]
fn challenge_9() {
    assert_eq!(
        pad_pkcs_7(b"YELLOW SUBMARINE".to_vec(), 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec()
    );
}
