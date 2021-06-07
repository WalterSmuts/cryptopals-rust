const MAX_KEY_SIZE: usize = 40;

pub fn hex_to_base64(hex: &str) -> String {
    base64::encode(hex::decode(hex).unwrap())
}

pub fn fixed_xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

pub fn single_char_xor_decrypt(cypher: &Vec<u8>, c: u8) -> Vec<u8> {
    let mut key = vec![];
    for _ in 0..cypher.len() {
        key.push(c);
    }
    fixed_xor(&cypher, &key)
}

pub fn get_english_score(s: &str) -> usize {
    let mut i = 0;
    for c in s.chars() {
        match c.to_uppercase().collect::<Vec<_>>().pop().unwrap() {
            ' ' => i += 6,
            'E' => i += 5,
            'A' => i += 4,
            'R' => i += 3,
            'I' => i += 2,
            'O' => i += 1,
            _ => (),
        }
    }
    i
}

pub fn most_likely_single_char_xor(cypher: &Vec<u8>) -> u8 {
    let mut max = 0;
    let mut best = 0;

    for byte in 0..u8::MAX {
        let decrypted_candidate = single_char_xor_decrypt(cypher, byte);
        let score = get_english_score(&String::from_utf8(decrypted_candidate).unwrap_or_default());
        if score > max {
            max = score;
            best = byte;
        }
    }
    best
}

pub fn single_char_xor_break(cypher: &Vec<u8>) -> Vec<u8> {
    let byte = most_likely_single_char_xor(cypher);
    single_char_xor_decrypt(cypher, byte)
}

pub fn multi_string_xor_detection(candidates: Vec<Vec<u8>>) -> Vec<u8> {
    let mut max = 0;
    let mut best = Vec::default();
    for candidate in candidates {
        let decrypted_candidate = single_char_xor_break(&candidate);
        let score = get_english_score(&String::from_utf8(decrypted_candidate).unwrap_or_default());
        if score > max {
            max = score;
            best = candidate;
        }
    }
    best
}

pub fn encrypt_repeating_key_xor(plain_text: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut repeating_key = Vec::default();
    while repeating_key.len() + key.len() < plain_text.len() {
        repeating_key.append(&mut key.clone());
    }
    repeating_key.append(&mut key[..plain_text.len() - repeating_key.len()].to_vec());
    fixed_xor(plain_text, &repeating_key)
}

pub fn hamming_distance(a: &Vec<u8>, b: &Vec<u8>) -> u32 {
    fixed_xor(a, b)
        .iter()
        .fold(0, |acc, x| acc + x.count_ones())
}

pub fn get_most_likely_key_sizes(cypher: &Vec<u8>, amount: usize) -> Vec<usize> {
    let mut contenders = Vec::new();
    for keysize in 2..MAX_KEY_SIZE {
        let mut hamming_distance_sum = 0;
        for idx in 0..(cypher.len() / MAX_KEY_SIZE / 2) {
            let a = &cypher[idx * keysize..(idx + 1) * keysize];
            let b = &cypher[(idx + 1) * keysize..(idx + 2) * keysize];
            hamming_distance_sum += hamming_distance(&a.to_vec(), &b.to_vec());
        }
        let normalized_hamming_distance = hamming_distance_sum as f64 / keysize as f64;
        contenders.push((keysize, normalized_hamming_distance));
    }
    contenders.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    contenders.iter().map(|a| a.0).take(amount).collect()
}

pub fn get_most_likely_key(cypher: &Vec<u8>, size: usize) -> Vec<u8> {
    let mut key = Vec::new();
    for start in 0..size {
        let sub_cypher = &cypher[start..];
        let sub_cypher = sub_cypher.to_vec().into_iter().step_by(size).collect();
        key.push(most_likely_single_char_xor(&sub_cypher));
    }
    key
}

pub fn variable_length_xor_break(cypher: Vec<u8>) -> Vec<u8> {
    let sizes = get_most_likely_key_sizes(&cypher, 1);
    let mut candidates = Vec::new();
    for size in sizes {
        let mut key = get_most_likely_key(&cypher, size);
        candidates.push(encrypt_repeating_key_xor(&cypher, &mut key));
    }
    candidates.sort_by(|a, b| {
        let a = get_english_score(&String::from_utf8(a.to_vec()).unwrap_or_default());
        let b = get_english_score(&String::from_utf8(b.to_vec()).unwrap_or_default());
        a.cmp(&b)
    });

    candidates.pop().unwrap()
}

#[test]
fn challenge_1() {
    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    );
}

#[test]
fn challenge_2() {
    assert_eq!(
        hex::encode(fixed_xor(
            &hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
            &hex::decode("686974207468652062756c6c277320657965").unwrap(),
        )),
        "746865206b696420646f6e277420706c6179",
    );
}

#[test]
fn challenge_3() {
    assert_eq!(
        String::from_utf8(single_char_xor_break(
            &hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap()
        ))
        .unwrap(),
        "Cooking MC's like a pound of bacon",
    );
}

#[test]
fn challenge_4() {
    use std::fs;
    let decrypted = multi_string_xor_detection(
        fs::read_to_string("data/4.txt")
            .unwrap()
            .lines()
            .map(|line| hex::decode(line).unwrap())
            .collect(),
    );
    assert_eq!(
        hex::encode(&decrypted),
        "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f",
    );
    assert_eq!(
        String::from_utf8(single_char_xor_break(&decrypted)).unwrap(),
        "Now that the party is jumping\n",
    );
}

#[test]
fn challenge_5() {
    assert_eq!(
        hex::encode(encrypt_repeating_key_xor(
            &b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec(),
            &b"ICE".to_vec(),
        )),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
    );
}

#[test]
fn hamming_distance_test() {
    assert_eq!(
        hamming_distance(&b"this is a test".to_vec(), &b"wokka wokka!!!".to_vec(),),
        37
    );
}

#[test]
fn challenge_6() {
    use std::fs;
    let original =
        base64::decode(fs::read_to_string("data/6.txt").unwrap().replace('\n', "")).unwrap();
    let decrypted = variable_length_xor_break(original);
    assert_eq!(
        String::from_utf8(decrypted).unwrap().replace(" \n", "\n"),
        fs::read_to_string("data/6-and-7-solved.txt").unwrap(),
    );
}

#[test]
fn challenge_7() {
    use openssl::symm::decrypt;
    use openssl::symm::Cipher;
    use std::fs;
    let cipher = Cipher::aes_128_ecb();
    let key = b"YELLOW SUBMARINE";
    let input =
        &base64::decode(fs::read_to_string("data/7.txt").unwrap().replace('\n', "")).unwrap();
    let decrypted = decrypt(cipher, key, None, &input).unwrap();
    assert_eq!(
        String::from_utf8(decrypted).unwrap().replace(" \n", "\n"),
        fs::read_to_string("data/6-and-7-solved.txt").unwrap(),
    );
}
