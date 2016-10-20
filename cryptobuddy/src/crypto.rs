extern crate openssl;

use openssl::crypto::symm;
use std::iter;



pub fn fixed_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len());
    let out: Vec<u8> = a.iter().zip(b.iter())
                               .map(|(x, y)| x ^ y )
                               .collect();
    out
}

pub fn single_byte_xor(stream: &[u8], key: u8) -> Vec<u8> {
    let key_stream: Vec<u8> = iter::repeat(key).take(stream.len()).collect();
    fixed_xor(&stream, &key_stream)
}

pub fn repeating_key_xor(stream: &[u8], key: &[u8]) -> Vec<u8> {
    let key_stream: Vec<u8> = key.iter().cycle().take(stream.len()).map(|&x| x).collect();
    fixed_xor(&stream, &key_stream)
}

pub fn detect_repeated_blocks(stream: &[u8], block_size: usize) -> bool {
    for (index, block) in stream.chunks(block_size).enumerate() {
        for sub_block in stream.chunks(block_size).skip(index + 1) {
            if block == sub_block {return true}
        }
    }
    false
}

pub fn pkcs7_pad(block: &[u8], block_size: usize) -> Vec<u8> {
    if (block.len() % block_size) == 0 {
        let output: Vec<u8> = block.iter()
                                   .cloned()
                                   .chain(iter::repeat(block_size as u8)
                                                 .take(block_size))
                                   .collect();
        return output
    }
    else {
        let residue: u8 = (block.len() % block_size) as u8;
        let output: Vec<u8> = block.iter()
                                   .cloned()
                                   .chain(iter::repeat(block_size as u8 - residue)
                                                 .take(block_size - residue as usize))
                                   .collect();

        return output
    }
}

pub fn aes_ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    debug_assert_eq!(16usize, key.len());
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16) {
        output.extend(aes_ecb_decrypt_raw(&block, &key))
    }
    trim_padding(&mut output);
    output
}

fn aes_ecb_decrypt_raw(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = [0u8; 32];
    let mut crypter = symm::Crypter::new(symm::Type::AES_128_ECB,
                                         symm::Mode::Decrypt,
                                         &key,
                                         None).unwrap();
    crypter.pad(false);
    crypter.update(&data, &mut output).expect("Encrypted Successfully");
    output.iter().cloned().take(16).collect()
}


pub fn aes_ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let data: Vec<u8> = pkcs7_pad(&data, key.len());
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16){
        output.extend(aes_ecb_encrypt_raw(&block, &key));
    }
    output
}

fn aes_ecb_encrypt_raw(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = [0u8; 32];
    let mut crypter = symm::Crypter::new(symm::Type::AES_128_ECB,
                                         symm::Mode::Encrypt,
                                         &key,
                                         None).unwrap();
    crypter.pad(false);
    crypter.update(&data, &mut output).expect("Encrypted Successfully");
    let output: Vec<u8> = output.iter().cloned().take(16).collect();
    output
}

pub fn aes_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let data = pkcs7_pad(&data, 16);
    let mut iv: Vec<u8> = iv.into();
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16) {
        let mut encrypt_block = fixed_xor(&block, &iv);
        encrypt_block = aes_ecb_encrypt_raw(&encrypt_block, &key);
        output.extend(encrypt_block.iter().cloned());
        iv = encrypt_block;
    }
    output
}

pub fn aes_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut iv: Vec<u8> = iv.into();
    let mut output = Vec::<u8>::new();
    for block in data.chunks(16) {
        let mut decrypt_block = aes_ecb_decrypt_raw(&block, &key);
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
        0 => if data.iter().cloned()
                           .rev()
                           .take(16)
                           .all(|z| z == 0) {return Some(16)}
                                       else {return None},

        u @ _ => if data.iter().cloned()
                               .rev()
                               .take(u as usize)
                               .all(|z| z == u) {return Some(u as usize)}
                                           else {return None}
    }
}


pub fn trim_padding(data: &mut Vec<u8>) -> () {
    let data_len = data.len(); // Non-lexical borrows pls
    match check_pkcs7_pad_size(&data) {
        None => (),
        Some(u) => data.resize(data_len - u, 0)
    }

}
