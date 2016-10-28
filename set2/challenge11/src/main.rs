extern crate cryptobuddy;
extern crate rand;

use cryptobuddy::{utils, crypto};
use cryptobuddy::crypto::EncryptionMode;

use std::fs::File;
use std::io::prelude::*;

fn load_data () -> Vec<u8> {
    let mut f = File::open("data/plaintext.txt").expect("Couldn't open file");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("File didn't parse so well.");
    s.into_bytes()
}

fn pick_random_encryption_mode() -> EncryptionMode {
    let mode: bool = rand::random();
    match mode {
        true => EncryptionMode::CBC,
        false => EncryptionMode::ECB
    }
}

fn encrypt_under_random_key(data: &[u8]) -> (EncryptionMode, Vec<u8>) {
    let mode = pick_random_encryption_mode();
    let key = utils::random_key();
    let iv = utils::random_key();
    let data = utils::pad_both_sides(data);

    match mode {
        EncryptionMode::ECB => {(mode, crypto::aes_ecb_encrypt(&data, &key))},
        EncryptionMode::CBC => {(mode, crypto::aes_cbc_encrypt(&data, &key, &iv))}
    }
}

fn main() {
    let plaintext = load_data();
    let (mode, encrypted_data) = encrypt_under_random_key(&plaintext);
    let guess = crypto::ecb_oracle(&encrypted_data);
    if mode == guess {println!("Guessed correctly: {:?}", mode);}
    else {println!("Guessed incorrectly: {:?} Actually: {:?}", guess, mode);}
}
