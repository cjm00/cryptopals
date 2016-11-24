extern crate cryptobuddy;
extern crate rustc_serialize;
extern crate rand;

use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;
use std::str;
use std::iter;
use std::collections::HashSet;

use rustc_serialize::base64::FromBase64;
use rand::Rng;
use cryptobuddy::{block, utils, pkcs7};

type UnencryptedBytes = Vec<u8>;
type EncryptedBytes = Vec<u8>;
type IV = Vec<u8>;

const KEYSIZE: usize = 16;

static DATA_PATH: &'static str = "data/17.txt";


struct CryptoServer {
    key: [u8; KEYSIZE],
    message: UnencryptedBytes,
}


impl CryptoServer {
    fn new(message: UnencryptedBytes) -> CryptoServer {
        let key = utils::random_key();
        CryptoServer {
            key: key,
            message: message,
        }
    }

    fn encrypted_message(&self) -> (EncryptedBytes, IV) {
        let iv = utils::random_key();
        let encrypted = block::aes_cbc_encrypt(&self.message, &self.key, &iv);
        (encrypted, iv.to_vec())
    }

    fn decrypt_message(&self,
                       message: &[u8],
                       iv: &[u8])
                       -> Result<(), block::BlockEncryptionError> {
        match block::aes_cbc_decrypt(message, &self.key, iv) {
            Ok(_) => Ok(()),
            Err(u) => Err(u),
        }
    }
}


fn pop_random_element<T>(collection: &mut Vec<T>) -> T {
    let index: usize = rand::thread_rng().gen_range(0, collection.len());
    collection.swap_remove(index)
}


fn load_data() -> Vec<UnencryptedBytes> {
    let f = File::open(DATA_PATH).unwrap();
    let f = BufReader::new(f);
    let l: Vec<String> = f.lines().collect::<Result<Vec<_>, _>>().unwrap();
    let l: Vec<UnencryptedBytes> = l.into_iter().map(|x| x.from_base64().unwrap()).collect();
    l
}


fn generate_padding_mask(size: usize) -> Vec<u8> {
    debug_assert!(size <= KEYSIZE);
    let output = vec![0u8; KEYSIZE - size];
    pkcs7::pad(&output, KEYSIZE)
}


fn padding_oracle_attack(server: CryptoServer) -> String {
    let (initial, iv) = server.encrypted_message();
    let mut known = Vec::<u8>::new();
    let mut forbidden = vec![HashSet::<u8>::new(); initial.len() + 1];


    // To conduct the attack against the first block we have to twiddle the IV
    'firstblock: loop {
        if known.len() < KEYSIZE {
            let target_chunk = initial.chunks(KEYSIZE).nth(0).unwrap();
            for g in 0..128u8 {
                if forbidden[known.len()].contains(&g) {
                    continue;
                }

                let mut guess_pred: Vec<u8> = iter::repeat(0u8)
                    .take(KEYSIZE - (known.len() + 1))
                    .chain(iter::once(g))
                    .chain(known.iter().cloned().rev())
                    .collect();
                guess_pred = utils::fixed_xor(&guess_pred, &generate_padding_mask(known.len() + 1));
                let corrupted_iv = utils::fixed_xor(&iv, &guess_pred);
                match server.decrypt_message(&target_chunk, &corrupted_iv) {
                    Ok(_) => {
                        known.push(g);
                        continue 'firstblock;
                    }
                    Err(_) => continue,
                }
            }
            loop {
                let mistake = known.pop().unwrap();
                if forbidden[known.len()].contains(&mistake) {
                    continue;
                } else {
                    forbidden[known.len()].insert(mistake);
                    break;
                }
            }
        } else {
            break;
        }
    }

    // for the rest of the blocks we twiddle the preceding block
    'laterblocks: loop {
        if known.len() < initial.len() {
            let target_chunk = known.len() / KEYSIZE;

            // C_x-1 = C_x-1 ^ P_x ^ Pad_byte
            for g in 1..128u8 {
                if forbidden[known.len()].contains(&g) {
                    continue;
                }
                let guess_pred: Vec<u8> = match known.len() % KEYSIZE {
                    0 => {
                        iter::repeat(0u8)
                            .take(KEYSIZE - 1)
                            .chain(iter::once(g))
                            .collect()
                    }
                    u => {
                        iter::repeat(0u8)
                            .take(KEYSIZE - (u + 1))
                            .chain(iter::once(g))
                            .chain(known.chunks(KEYSIZE).last().unwrap().iter().cloned().rev())
                            .collect()
                    }
                };
                debug_assert_eq!(guess_pred.len(), KEYSIZE);


                let mut pred_block: Vec<u8> = initial.chunks(KEYSIZE)
                    .nth(target_chunk - 1)
                    .unwrap()
                    .to_vec();

                pred_block = utils::fixed_xor(&pred_block,
                                              &generate_padding_mask((known.len() % KEYSIZE) + 1));

                pred_block = utils::fixed_xor(&pred_block, &guess_pred);
                let input: Vec<u8> = pred_block.iter()
                    .cloned()
                    .chain(initial.chunks(KEYSIZE).nth(target_chunk).unwrap().iter().cloned())
                    .collect();

                match server.decrypt_message(&input, &iv) {
                    Ok(_) => {
                        known.push(g);
                        continue 'laterblocks;
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
            // If we hit a point where we can't go forward, backtrack and try again.
            loop {
                let mistake = known.pop().unwrap();
                if forbidden[known.len()].contains(&mistake) {
                    continue;
                } else {
                    forbidden[known.len()].insert(mistake);
                    break;
                }
            }
        } else {
            break;
        }
    }


    let mut known: Vec<u8> = known.chunks(KEYSIZE).flat_map(|s| s.iter().cloned().rev()).collect();
    pkcs7::trim(&mut known).expect("Invalid padding on extracted message");
    let out = String::from_utf8(known).unwrap();
    out
}


fn main() {
    let datalist = load_data();
    for data in datalist {
        let server = CryptoServer::new(data);
        println!("{}", padding_oracle_attack(server));
    }
}
