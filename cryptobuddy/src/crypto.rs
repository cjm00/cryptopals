extern crate crypto as rust_crypto;

use rust_crypto::{buffer, aes, blockmodes};
use rust_crypto::buffer::{ ReadBuffer, WriteBuffer};
use std::iter;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum EncryptionMode {
    ECB,
    CBC
}

pub fn fixed_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x ^ y)
        .collect()
}

pub fn single_byte_xor(stream: &[u8], key: u8) -> Vec<u8> {
    let key_stream: Vec<u8> = iter::repeat(key).take(stream.len()).collect();
    fixed_xor(stream, &key_stream)
}

pub fn repeating_key_xor(stream: &[u8], key: &[u8]) -> Vec<u8> {
    let key_stream: Vec<u8> = key.iter().cloned().cycle().take(stream.len()).collect();
    fixed_xor(stream, &key_stream)
}

pub fn detect_repeated_blocks(stream: &[u8], block_size: usize) -> bool {
    for (index, block) in stream.chunks(block_size).enumerate() {
        if stream.chunks(block_size).skip(index + 1).any(|z| z == block) {
            return true;
        }
    }
    false
}

pub fn pkcs7_pad(block: &[u8], block_size: usize) -> Vec<u8> {
    if (block.len() % block_size) == 0 {
        block.iter()
            .cloned()
            .chain(iter::repeat(block_size as u8).take(block_size))
            .collect()
    } else {
        let residue: u8 = (block.len() % block_size) as u8;
        block.iter()
            .cloned()
            .chain(iter::repeat(block_size as u8 - residue).take(block_size - residue as usize))
            .collect()

    }
}

pub fn aes_ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    debug_assert_eq!(16usize, key.len());
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16) {
        output.extend(aes_ecb_decrypt_raw(block, key))
    }
    trim_padding(&mut output);
    output
}

fn aes_ecb_decrypt_raw(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buf = [0u8; 16];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buf);
    let mut encrypter = aes::ecb_decryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);
    encrypter.decrypt(&mut read_buffer, &mut write_buffer, true).expect("Decryption unsucessful");

    let mut output = Vec::<u8>::new();
    output.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
    output
}


pub fn aes_ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let data: Vec<u8> = pkcs7_pad(data, key.len());
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16) {
        output.extend(aes_ecb_encrypt_raw(block, key));
    }
    output
}

fn aes_ecb_encrypt_raw(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buf = [0u8; 16];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buf);
    let mut encrypter = aes::ecb_encryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);
    encrypter.encrypt(&mut read_buffer, &mut write_buffer, true).expect("Encryption unsucessful");

    let mut output = Vec::<u8>::new();
    output.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
    output
}

pub fn aes_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let data = pkcs7_pad(data, 16);
    let mut iv: Vec<u8> = iv.into();
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16) {
        let mut encrypt_block = fixed_xor(block, &iv);
        encrypt_block = aes_ecb_encrypt_raw(&encrypt_block, key);
        output.extend(encrypt_block.iter().cloned());
        iv = encrypt_block;
    }
    output
}

pub fn aes_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut iv: Vec<u8> = iv.into();
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16) {
        let mut decrypt_block = aes_ecb_decrypt_raw(block, key);
        decrypt_block = fixed_xor(&decrypt_block, &iv);
        output.extend(decrypt_block);
        iv = block.into();
    }
    trim_padding(&mut output);
    output
}

pub fn check_pkcs7_pad_size(data: &[u8]) -> Option<usize> {
    debug_assert!(data.len() >= 16);
    match data.iter().cloned().last().unwrap() {
        0 => {
            if data.iter()
                .cloned()
                .rev()
                .take(16)
                .all(|z| z == 0) {
                Some(16)
            } else {
                None
            }
        }

        u => {
            if data.iter()
                .cloned()
                .rev()
                .take(u as usize)
                .all(|z| z == u) {
                Some(u as usize)
            } else {
                None
            }
        }
    }
}


pub fn trim_padding(data: &mut Vec<u8>) -> () {
    let data_len = data.len(); // Non-lexical borrows pls
    match check_pkcs7_pad_size(data) {
        None => (),
        Some(u) => data.resize(data_len - u, 0),
    }

}

pub fn ecb_oracle(data: &[u8]) -> EncryptionMode {
    match detect_repeated_blocks(data, 16) {
        true => EncryptionMode::ECB,
        false => EncryptionMode::CBC
    }
}
