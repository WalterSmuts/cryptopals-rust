pub fn hex_to_base64(hex: &str) -> String {
    base64::encode(hex::decode(hex).unwrap())
}

pub fn fixed_xor(a: &str, b: &str) -> String {
    let a = hex::decode(a.as_bytes()).unwrap();
    let b = hex::decode(b.as_bytes()).unwrap();
    let z: Vec<u8> = a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    hex::encode(z)
}

pub fn single_char_xor_decrypt(cypher: &str, c: u8) -> String {
    let mut key = vec![];
    for _ in 0..hex::encode(&cypher).len() {
        key.push(c);
    }
    String::from_utf8(hex::decode(fixed_xor(cypher, &hex::encode(key))).unwrap())
        .unwrap_or_default()
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

pub fn single_char_xor_break(cypher: &str) -> String {
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

pub fn multi_string_xor_detection(strings: std::str::Lines) -> String {
    let mut max = 0;
    let mut best = String::default();
    for string in strings {
        let decrypted_candidate = single_char_xor_break(string);
        if get_english_score(&decrypted_candidate) > max {
            max = get_english_score(&decrypted_candidate);
            best = string.to_string();
        }
    }
    best
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
        fixed_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
        ),
        "746865206b696420646f6e277420706c6179",
    );
}

#[test]
fn challenge_3() {
    assert_eq!(
        single_char_xor_break(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        ),
        "Cooking MC's like a pound of bacon",
    );
}

#[test]
fn challenge_4() {
    use std::fs;
    let decrypted = multi_string_xor_detection(fs::read_to_string("data/4.txt").unwrap().lines());
    assert_eq!(
        decrypted,
        "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f",
    );
    assert_eq!(
        single_char_xor_break(&decrypted),
        "Now that the party is jumping\n",
    );
}
