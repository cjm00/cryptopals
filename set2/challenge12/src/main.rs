extern crate cryptobuddy;
extern crate rustc_serialize;

use rustc_serialize::base64::FromBase64;
use cryptobuddy::{crypto, utils};

use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;
use std::iter;
use std::str;


struct SecretBlob {
    secret: Vec<u8>,
    key: Vec<u8>,
}

impl SecretBlob {
    fn new_blob(message: &[u8]) -> SecretBlob {
        SecretBlob {
            secret: message.into(),
            key: utils::random_key().iter().cloned().collect(),
        }
    }

    fn encrypt_with_prefix(&self, prefix: &[u8]) -> Vec<u8> {
        let prefixed_secret: Vec<u8> =
            prefix.iter().cloned().chain(self.secret.iter().cloned()).collect();
        crypto::aes_ecb_encrypt(&prefixed_secret, &self.key)
    }
}

fn load_data() -> Vec<u8> {
    let mut f = File::open("data/secret.txt").expect("Couldn't open file");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("File didn't go so well.");
    let s = s.from_base64().expect("Couldn't decode secret from base64");
    s
}

fn matching_prefix_length(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|&(x, y)| *x == *y).count()
}


fn find_block_size(secret: &SecretBlob) -> usize {
    let mut block_size = 0usize;
    let mut padding = Vec::<u8>::with_capacity(32);

    loop {
        let pad1 = secret.encrypt_with_prefix(&padding);
        padding.push(b'A');
        let pad2 = secret.encrypt_with_prefix(&padding);
        let common_prefix_size = matching_prefix_length(&pad1, &pad2);
        if common_prefix_size == 0 {
            continue;
        }
        if common_prefix_size == block_size {
            return block_size;
        } else {
            block_size = common_prefix_size
        };
    }
}


fn test_for_ecb_mode(secret: &SecretBlob) -> bool {
    let prefix: Vec<u8> = iter::repeat(b'A').take(200).collect();
    let encrypted_data = secret.encrypt_with_prefix(&prefix);
    match crypto::ecb_oracle(&encrypted_data) {
        crypto::EncryptionMode::ECB => true,
        crypto::EncryptionMode::CBC => false,
    }
}


fn discover_secret_len(secret: &SecretBlob) -> usize {
    let mut prefix = Vec::<u8>::new();
    let zero_pad_size = secret.encrypt_with_prefix(&prefix).len();
    prefix.push(b'A');
    while zero_pad_size == secret.encrypt_with_prefix(&prefix).len() {
        prefix.push(b'A');
    }

    (zero_pad_size - prefix.len())
}


fn decrypt_ecb_blob(secret: &SecretBlob) -> Vec<u8> {
    let mut known_bytes = Vec::<u8>::new();

    let secret_len = discover_secret_len(&secret);
    let block_size = find_block_size(&secret);

    while known_bytes.len() < secret_len {
        let latest_byte = decrypt_byte(known_bytes.len(), &known_bytes, &secret, block_size);
        known_bytes.push(latest_byte);

    }

    known_bytes
}

fn decrypt_byte(byte: usize, known: &[u8], secret: &SecretBlob, block_size: usize) -> u8 {
    // This Hashmap is a mapping from encrypted blocks of [u8] to the unencrypted last byte
    let mut reverse_block_lookup = HashMap::<Vec<u8>, u8>::new();
    let pad_size = (block_size - 1) - (byte % block_size);
    let block_number = (byte + pad_size) / block_size;


    if block_number == 0 {
        for x in 0..128u8 {
            let test_block: Vec<u8> = iter::repeat(b'A')
                .take(pad_size)
                .chain(known.iter().cloned())
                .chain(iter::once(x))
                .collect();
            debug_assert_eq!(test_block.len(), 16);

            let test_block_encrypted: Vec<u8> = secret.encrypt_with_prefix(&test_block)
                .iter()
                .cloned()
                .take(16)
                .collect();

            reverse_block_lookup.insert(test_block_encrypted, x);
        }
        let prefix: Vec<u8> = iter::repeat(b'A').take(pad_size).collect();
        let encrypted_block: Vec<u8> =
            secret.encrypt_with_prefix(&prefix).iter().cloned().take(16).collect();

        match reverse_block_lookup.get(&encrypted_block) {
            Some(x) => *x,
            None => unreachable!(),
        }

    } else {
        for x in 0..128u8 {
            let test_block: Vec<u8> =
                known[known.len() - 15..].iter().cloned().chain(iter::once(x)).collect();
            debug_assert_eq!(test_block.len(), 16);

            let test_block_encrypted: Vec<u8> = secret.encrypt_with_prefix(&test_block)
                .iter()
                .cloned()
                .take(16)
                .collect();

            reverse_block_lookup.insert(test_block_encrypted, x);
        }

        let prefix: Vec<u8> = iter::repeat(b'A').take(pad_size).collect();
        let encrypted_block: Vec<u8> = secret.encrypt_with_prefix(&prefix)
            .chunks(block_size)
            .nth(block_number)
            .unwrap()
            .into();
            
        match reverse_block_lookup.get(&encrypted_block) {
            Some(x) => *x,
            None => unreachable!(),
        }
    }

}

fn main() {
    let secret_message = load_data();
    let secret = SecretBlob::new_blob(&secret_message);
    let block_size = find_block_size(&secret);
    if test_for_ecb_mode(&secret) {
        println!("Detected ECB mode with block size: {}", block_size);
    };
    let decrypted_message = decrypt_ecb_blob(&secret);
    println!("{}", str::from_utf8(&decrypted_message).unwrap());
}
