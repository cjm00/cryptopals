extern crate cryptobuddy;

use cryptobuddy::{block, utils};

use std::str;
use std::iter;

const KEYSIZE: usize = 16;

static PREFIX: &'static str = "comment1=cooking%20MCs;userdata=";
static SUFFIX: &'static str = ";comment2=%20like%20a%20pound%20of%20bacon";
static TARGET: &'static str = ";admin=true;";



fn embed_and_encrypt(data: String, key: &[u8], iv: &[u8]) -> Vec<u8> {
    data.replace(";", "%3B");
    data.replace("=", "%3D");
    let chained_message: Vec<u8> = PREFIX.as_bytes()
        .iter()
        .cloned()
        .chain(data.as_bytes().iter().cloned())
        .chain(SUFFIX.as_bytes().iter().cloned())
        .collect();

    block::aes_cbc_encrypt(&chained_message, key, iv)
}


fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    block::aes_cbc_decrypt(encrypted_data, key, iv)
}

fn check_for_admin(data: &[u8]) -> bool {
    String::from_utf8_lossy(data).contains(TARGET)
}

fn main() {
    let key = utils::random_key();
    let iv = utils::random_key();

    let prefix_len = PREFIX.as_bytes().len();
    let pad_len = (KEYSIZE - (prefix_len % KEYSIZE)) % KEYSIZE;
    let skip = (prefix_len + pad_len) / KEYSIZE;

    let first_input: Vec<u8> = iter::repeat(b'A').take(pad_len + KEYSIZE * 2).collect();
    let first_input = String::from_utf8(first_input).unwrap();
    let mut first_output = embed_and_encrypt(first_input, &key, &iv);

    let mut corrupted_block: Vec<u8> = iter::repeat(b'A')
        .take(KEYSIZE - TARGET.len())
        .chain(TARGET.as_bytes().iter().cloned())
        .collect();

    let plaintext_block: Vec<u8> = iter::repeat(b'A').take(KEYSIZE).collect();
    corrupted_block = utils::fixed_xor(&corrupted_block, &plaintext_block);


    {
        let original_block = first_output.chunks(KEYSIZE).nth(skip).unwrap();
        corrupted_block = utils::fixed_xor(&corrupted_block, &original_block);
    }

    {
        let mut target_block = first_output.chunks_mut(KEYSIZE).nth(skip).unwrap();
        target_block.copy_from_slice(&corrupted_block);
    }

    if check_for_admin(&decrypt(&first_output, &key, &iv)) {
        println!("Admin Access Granted!");
    }

}
