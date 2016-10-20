extern crate cryptobuddy;
extern crate rustc_serialize;

use rustc_serialize::hex::{FromHex};
use cryptobuddy::{crypto, freq_analysis};
use std::str;


fn main() {
    let target = "1b37373331363f78151b7f2b783431333d\
                  78397828372d363c78373e783a393b3736".from_hex().unwrap();
    let mut output: Vec<u8> = vec![];
    let mut score = 100f64;
    let mut key: char = 'a';

    for x in b'A'..b'z'+1 {
        let decrypt = crypto::single_byte_xor(&target, x);
        let temp_score = freq_analysis::text_score(&decrypt);
        if temp_score < score {
            score = temp_score;
            output = decrypt.clone();
            key = x as char;
        }
    }
    println!("{}", str::from_utf8(&output).unwrap());
    println!("Key: {}", key);
    println!("{}", score);
}
