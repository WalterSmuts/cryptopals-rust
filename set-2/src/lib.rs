use openssl::symm::decrypt;
use openssl::symm::encrypt;
use openssl::symm::Cipher;
use set_1::fixed_xor;

pub fn pad_pkcs_7(mut input: Vec<u8>, block_size: usize) -> Vec<u8> {
    let num_pad_bytes = block_size - (input.len() % block_size);
    input.append(&mut vec![num_pad_bytes as u8; num_pad_bytes]);
    input
}

pub fn decrypt_aes_cbc(mut cypher_text: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypted = Vec::new();

    let mut prev_block = iv;
    while cypher_text.len() > 15 {
        let mut block: Vec<u8> = cypher_text.drain(0..16).collect();

        // Add padding block to comply with openssl pkcs_7 requirement
        block.append(&mut encrypt(cipher, &key, None, &pad_pkcs_7(Vec::new(), 16)).unwrap());

        let decrypted_ecb_block = decrypt(cipher, &key, None, &block).unwrap();

        // Remove padding added earlier
        let decrypted_ecb_block = decrypted_ecb_block[0..16].to_vec();

        decrypted.append(&mut fixed_xor(&prev_block, &decrypted_ecb_block));
        prev_block = block;
    }
    decrypted
}

#[test]
fn challenge_9() {
    assert_eq!(
        pad_pkcs_7(b"YELLOW SUBMARINE".to_vec(), 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec()
    );
}

#[test]
fn challenge_10() {
    use std::fs;
    let cypher_text =
        base64::decode(fs::read_to_string("data/10.txt").unwrap().replace('\n', "")).unwrap();
    let key = b"YELLOW SUBMARINE".to_vec();
    let iv = vec![0; 16];
    let decoded = String::from_utf8(decrypt_aes_cbc(cypher_text, key, iv)).unwrap();
    assert!(decoded.len() != 0);
}
