extern crate cryptobuddy;
extern crate rand;

use cryptobuddy::{utils, crypto};
use rand::Rng;

use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;
use std::iter;
use std::str;

const KEYSIZE: usize = 16;
const PAD: u8 = b'A';


struct SecretBlob {
    secret: Vec<u8>,
    prefix: Vec<u8>,
    key: [u8; KEYSIZE],
}


impl SecretBlob {
    fn new_blob(message: &[u8]) -> SecretBlob {
        let mut rng = rand::thread_rng();
        let prefix_length = (rng.next_u64() % 64) as usize;
        SecretBlob {
            secret: message.into(),
            key: utils::random_key(),
            prefix: rng.gen_iter().take(prefix_length).collect(),
        }
    }

    fn encrypt_with_infix(&self, infix: &[u8]) -> Vec<u8> {
        let infixed_secret: Vec<u8> = self.prefix
            .iter()
            .cloned()
            .chain(infix.iter().cloned())
            .chain(self.secret.iter().cloned())
            .collect();
        crypto::aes_ecb_encrypt(&infixed_secret, &self.key)
    }
}


fn load_data() -> Vec<u8> {
    let mut f = File::open("data/secret.txt").expect("Couldn't open file");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("File didn't go so well.");
    s.into()
}


fn discover_prefix_len(secret: &SecretBlob) -> usize {
    let mut blob = Vec::<u8>::new();
    let block_index;
    loop {
        blob.push(b'A');
        match detect_repeating_blocks(&secret.encrypt_with_infix(&blob)) {
            None => continue,
            Some(x) => {
                block_index = x;
                break;
            }
        }
    }
    (block_index * KEYSIZE) - (blob.len() % KEYSIZE)
}


fn detect_repeating_blocks(data: &[u8]) -> Option<usize> {
    // if two adjacent identical blocks of size KEYSIZE exist,
    // returns the index of the first block
    for (index, block) in data.chunks(KEYSIZE).enumerate() {
        match data.chunks(KEYSIZE).nth(index + 1) {
            Some(next_block) => {
                if block == next_block {
                    return Some(index);
                }
            }
            None => return None,
        }
    }
    None
}


fn discover_suffix_len(secret: &SecretBlob, prefix_len: usize) -> usize {
    let mut infix = Vec::<u8>::new();
    let zero_infix_size = secret.encrypt_with_infix(&infix).len();
    infix.push(b'A');
    while zero_infix_size == secret.encrypt_with_infix(&infix).len() {
        infix.push(b'A');
    }
    (zero_infix_size - infix.len()) - prefix_len
}


fn decrypt_blob(secret: &SecretBlob) -> Vec<u8> {
    let mut known_bytes = Vec::<u8>::new();
    let prefix_len = discover_prefix_len(&secret);
    let suffix_len = discover_suffix_len(&secret, prefix_len);
    while known_bytes.len() < suffix_len {
        let latest_byte = decrypt_infix_byte(&known_bytes, prefix_len, &secret);
        known_bytes.push(latest_byte);
    }
    known_bytes
}


fn decrypt_infix_byte(known: &[u8], prefix_len: usize, secret: &SecretBlob) -> u8 {
    let mut reverse_block_lookup = HashMap::<Vec<u8>, u8>::new();
    let base_pad = (KEYSIZE) - (prefix_len % KEYSIZE);
    let pad_size = (KEYSIZE - 1) - (known.len() % KEYSIZE);
    let block_number = known.len() / KEYSIZE;
    let skip = (prefix_len + base_pad) / KEYSIZE;

    if block_number == 0 {
        for x in 0..128u8 {
            let test_infix: Vec<u8> = iter::repeat(PAD)
                .take(base_pad + pad_size)
                .chain(known.iter().cloned())
                .chain(iter::once(x))
                .collect();

            let enc_infix: Vec<u8> = secret.encrypt_with_infix(&test_infix)
                .chunks(KEYSIZE)
                .nth(skip)
                .unwrap()
                .into();

            reverse_block_lookup.insert(enc_infix, x);
        }

        let infix: Vec<u8> = iter::repeat(PAD).take(base_pad + pad_size).collect();
        let enc_infix: Vec<u8> =
            secret.encrypt_with_infix(&infix).chunks(KEYSIZE).nth(skip).unwrap().into();

        match reverse_block_lookup.get(&enc_infix) {
            Some(x) => *x,
            None => unreachable!(),
        }
    } else {
        for x in 0..128u8 {
            let test_infix: Vec<u8> = iter::repeat(PAD)
                .take(base_pad)
                .chain(known[known.len() - (KEYSIZE - 1)..].iter().cloned())
                .chain(iter::once(x))
                .collect();

            let enc_infix: Vec<u8> = secret.encrypt_with_infix(&test_infix)
                .chunks(KEYSIZE)
                .nth(skip)
                .unwrap()
                .into();

            reverse_block_lookup.insert(enc_infix, x);
        }

        let infix: Vec<u8> = iter::repeat(PAD).take(base_pad + pad_size).collect();
        let enc_infix: Vec<u8> = secret.encrypt_with_infix(&infix)
            .chunks(KEYSIZE)
            .nth(skip + block_number)
            .unwrap()
            .into();

        match reverse_block_lookup.get(&enc_infix) {
            Some(x) => *x,
            None => unreachable!(),
        }
    }
}

fn main() {
    let secret = SecretBlob::new_blob(&load_data());
    let decrypted_secret = decrypt_blob(&secret);
    println!("{}", str::from_utf8(&decrypted_secret).unwrap());
}
