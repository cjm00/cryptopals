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

fn encrypt_under_random_key(data: &[u8]) -> () {
    let mode = pick_random_encryption_mode();
}

fn main() {
    let plaintext = load_data();
    let test_data = utils::pad_both_sides(&plaintext);
    println!("Done.");
}
