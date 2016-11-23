use rust_crypto::{buffer, aes, blockmodes};
use rust_crypto::buffer::{ReadBuffer, WriteBuffer};

use pkcs7;
use utils;

const KEYSIZE: usize = 16;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum EncryptionMode {
    ECB,
    CBC,
}


#[derive(Debug, Copy, Clone)]
pub enum BlockEncryptionError {
    DecryptionError,
    PaddingError,
}


pub fn aes_ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    debug_assert_eq!(KEYSIZE, key.len());
    let mut output = Vec::<u8>::new();
    for block in data.chunks(KEYSIZE) {
        output.extend(aes_ecb_decrypt_raw(block, key))
    }
    pkcs7::trim(&mut output).expect("Invalid Padding");
    output
}


fn aes_ecb_decrypt_raw(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buf = [0u8; KEYSIZE];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buf);
    let mut encrypter = aes::ecb_decryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);
    encrypter.decrypt(&mut read_buffer, &mut write_buffer, true).expect("Decryption unsucessful");

    let mut output = Vec::<u8>::new();
    output.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
    output
}


pub fn aes_ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let data: Vec<u8> = pkcs7::pad(data, key.len());
    let mut output = Vec::<u8>::new();
    for block in data.chunks(KEYSIZE) {
        output.extend(aes_ecb_encrypt_raw(block, key));
    }
    output
}


fn aes_ecb_encrypt_raw(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buf = [0u8; KEYSIZE];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buf);
    let mut encrypter = aes::ecb_encryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);
    encrypter.encrypt(&mut read_buffer, &mut write_buffer, true).expect("Encryption unsucessful");

    let mut output = Vec::<u8>::new();
    output.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
    output
}


pub fn aes_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let data = pkcs7::pad(data, KEYSIZE);
    let mut iv: Vec<u8> = iv.into();
    let mut output = Vec::<u8>::new();
    for block in data.chunks(KEYSIZE) {
        let mut encrypt_block = utils::fixed_xor(block, &iv);
        encrypt_block = aes_ecb_encrypt_raw(&encrypt_block, key);
        output.extend(encrypt_block.iter().cloned());
        iv = encrypt_block;
    }
    output
}


pub fn aes_cbc_decrypt(data: &[u8],
                       key: &[u8],
                       iv: &[u8])
                       -> Result<Vec<u8>, BlockEncryptionError> {

    let mut iv: Vec<u8> = iv.into();
    let mut output = Vec::<u8>::new();
    for block in data.chunks(KEYSIZE) {
        let mut decrypt_block = aes_ecb_decrypt_raw(block, key);
        decrypt_block = utils::fixed_xor(&decrypt_block, &iv);
        output.extend(decrypt_block);
        iv = block.into();
    }
    match pkcs7::trim(&mut output) {
        Ok(_) => Ok(output),
        Err(_) => Err(BlockEncryptionError::PaddingError),
    }

}


pub fn ecb_oracle(data: &[u8]) -> EncryptionMode {
    if utils::detect_repeated_blocks(data, KEYSIZE) {
        EncryptionMode::ECB
    } else {
        EncryptionMode::CBC
    }
}


#[cfg(test)]
mod block_crypto_tests {
    use super::*;
    use std::iter;
    #[test]
    fn aes_cbc_test() {
        let iv: Vec<u8> = iter::repeat(2u8).take(KEYSIZE).collect();
        let key: Vec<u8> = "YELLOW SUBMARINE".into();
        let test_data: Vec<u8> = "THIS IS A TEST OF CBCTHIS IS A TEST OF CBC".into();
        let encrypt_test_data = aes_cbc_encrypt(&test_data, &key, &iv);
        let decrypt_test_data = aes_cbc_decrypt(&encrypt_test_data, &key, &iv).unwrap();
        assert_eq!(test_data, decrypt_test_data);
    }
}
