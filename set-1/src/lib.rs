pub fn hex_to_base64(hex: String) -> String {
    base64::encode(hex::decode(hex).unwrap())
}

pub fn fixed_xor(a: String, b: String) -> String {
    let a = hex::decode(a.as_bytes()).unwrap();
    let b = hex::decode(b.as_bytes()).unwrap();
    let z: Vec<u8> = a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    hex::encode(z)
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
