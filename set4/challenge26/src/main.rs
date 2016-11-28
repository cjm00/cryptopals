extern crate cryptobuddy;
extern crate rand;

use cryptobuddy::{stream, utils};

use std::str;

static PREFIX: &'static str = "comment1=cooking%20MCs;userdata=";
static SUFFIX: &'static str = ";comment2=%20like%20a%20pound%20of%20bacon";
static TARGET: &'static str = ";admin=true;";

fn embed_and_encrypt(data: String, crypter: &stream::CTR) -> Vec<u8> {
    data.replace(";", "%3B");
    data.replace("=", "%3D");
    let chained_message: Vec<u8> = PREFIX.as_bytes()
        .iter()
        .cloned()
        .chain(data.as_bytes().iter().cloned())
        .chain(SUFFIX.as_bytes().iter().cloned())
        .collect();

    crypter.crypt(&chained_message)
}

fn check_for_admin(data: &[u8]) -> bool {
    String::from_utf8_lossy(data).contains(TARGET)
}

fn main() {
    let crypter = stream::CTR::new(&utils::random_key(), &utils::random_nonce()).unwrap();
    let input: String = "AAAAAAAAAAAAAAAA".into();

    let mut ciphertext = embed_and_encrypt(input, &crypter);
    let start = PREFIX.len() + (16 - TARGET.len());
    let end = PREFIX.len() + 16;

    let corruption = utils::fixed_xor(&ciphertext[start..end], TARGET.as_bytes());
    let corruption = utils::fixed_xor(&corruption, &"AAAAAAAAAAAA".as_bytes());

    {
        let s = &mut ciphertext[start..end];
        s.copy_from_slice(&corruption);
    }

    let ciphertext = crypter.crypt(&ciphertext);

    if check_for_admin(&ciphertext) {
        println!("Admin Granted!");
    }

}
