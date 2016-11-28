extern crate cryptobuddy;
extern crate rustc_serialize;

use std::fs::File;
use std::io::prelude::*;
use std::str;

use cryptobuddy::{stream, utils, block};
use rustc_serialize::base64::FromBase64;

struct CryptoServer {
    crypter: stream::CTR,
    ciphertext: Vec<u8>,
}

impl CryptoServer {
    pub fn new(data: &[u8]) -> CryptoServer {
        let key = utils::random_key();
        let nonce = utils::random_nonce();
        let crypter = stream::CTR::new(&key, &nonce).expect("Unable to initialize CTR");
        let enc_data = crypter.crypt(data);
        CryptoServer {
            crypter: crypter,
            ciphertext: enc_data,
        }
    }

    pub fn get_data(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }

    pub fn edit(&mut self, offset: usize, newtext: &[u8]) -> Result<usize, ()> {
        if offset + newtext.len() > self.ciphertext.len() {
            return Err(());
        }
        let new_ciphertext: Vec<u8> = self.crypter
            .iter()
            .skip(offset)
            .zip(newtext.iter().cloned())
            .map(|(x, y)| x ^ y)
            .collect();

        let original = &mut self.ciphertext[offset..(offset + newtext.len())];
        original.copy_from_slice(&new_ciphertext);
        Ok(newtext.len())
    }
}

fn load_data() -> Vec<u8> {
    let mut f = File::open("data/25.txt").expect("Couldn't open file");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("File didn't go so well.");
    s.from_base64().expect("Unable to decode file from base64")
}

fn main() {
    let key: Vec<u8> = "YELLOW SUBMARINE".into();
    let data = block::aes_ecb_decrypt(&load_data(), &key);
    let mut server = CryptoServer::new(&data);

    let original_ciphertext = server.get_data().to_owned();
    let zeroes: Vec<u8> = vec![0u8; original_ciphertext.len()];
    server.edit(0, &zeroes).unwrap();
    
    let new_ciphertext = server.get_data().to_owned();
    let plaintext = utils::fixed_xor(&original_ciphertext, &new_ciphertext);
    println!("{}", String::from_utf8_lossy(&plaintext));

}
