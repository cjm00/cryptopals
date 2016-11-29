extern crate cryptobuddy;

use cryptobuddy::{block, utils};

fn main() {

    let key = utils::random_key();
    let message: Vec<u8> = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean \
                            commodo ligula eget dolor. Aenean massa.".into();
    let mut ciphertext = block::aes_cbc_encrypt(&message, &key, &key);

    {
    let (block1, rest) = ciphertext.split_at_mut(16);
    let (block2, rest) = rest.split_at_mut(16);
    let (block3, _) = rest.split_at_mut(16);

    block3.copy_from_slice(block1);
    block2.copy_from_slice(&vec![0u8; 16]);
    }

    let corrupted_ciphertext = block::aes_cbc_decrypt(&ciphertext, &key, &key).unwrap();
    let new_key = utils::fixed_xor(&corrupted_ciphertext[0..16], &corrupted_ciphertext[32..48]);

    assert_eq!(key, new_key.as_slice());
    println!("Key found: {:?}", new_key);
}
