pub fn hex_to_base64(hex: String) -> String {
    base64::encode(hex::decode(hex).unwrap())
}

pub fn fixed_xor(a: String, b: String) -> String {
    let a = hex::decode(a.as_bytes()).unwrap();
    let b = hex::decode(b.as_bytes()).unwrap();
    let z: Vec<u8> = a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    hex::encode(z)
}

pub fn single_char_xor_decrypt(cypher: String, c: u8) -> String {
    let mut key = vec![];
    for _ in 0..hex::encode(&cypher).len() {
        key.push(c);
    }
    String::from_utf8(hex::decode(fixed_xor(cypher, hex::encode(key))).unwrap()).unwrap_or_default()
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

pub fn single_char_xor_break(cypher: String) -> String {
    let mut max = 0;
    let mut best = String::default();

    for byte in 0..u8::MAX {
        let decrypted_candidate = single_char_xor_decrypt(cypher.clone(), byte);
        if get_english_score(&decrypted_candidate) > max {
            max = get_english_score(&decrypted_candidate);
            best = decrypted_candidate.clone();
        }
    }
    best
}

#[test]
fn challenge_1() {
    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string()),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    );
}

#[test]
fn challenge_2() {
    assert_eq!(
        fixed_xor(
            "1c0111001f010100061a024b53535009181c".to_string(),
            "686974207468652062756c6c277320657965".to_string(),
        ),
        "746865206b696420646f6e277420706c6179",
    );
}

#[test]
fn challenge_3() {
    assert_eq!(
        single_char_xor_break(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string()
        ),
        "Cooking MC's like a pound of bacon",
    );
}
