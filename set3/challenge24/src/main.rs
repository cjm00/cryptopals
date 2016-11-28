extern crate cryptobuddy;
extern crate rand;

use std::iter;

use cryptobuddy::{stream, utils};
use rand::Rng;


fn main() {
    let mut rng = rand::thread_rng();
    let pad_length: u8 = rand::random();
    let seed: u16 = rand::random();
    let crypter = stream::MTStream::new(seed);

    let known_message: Vec<u8> = iter::repeat(b'A').take(14).collect();

    let plaintext: Vec<u8> = rng.gen_iter::<u8>().take(pad_length as usize).chain(known_message.iter().cloned()).collect();
    let ciphertext: Vec<u8> = crypter.crypt(&plaintext);

    let known_keystream = utils::fixed_xor(&ciphertext[ciphertext.len() - 14..], &known_message);

    for t in 0..65535u16 {
        let new_crypter = stream::MTStream::new(t);
        let new_keystream: Vec<u8> = new_crypter.iter().take(ciphertext.len()).collect();
        if &new_keystream[new_keystream.len() - 14..] == known_keystream.as_slice() {
            assert_eq!(t, seed);
            println!("Found seed: {}", t);
        }
    }
}
