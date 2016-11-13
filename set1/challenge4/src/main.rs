extern crate cryptobuddy;
extern crate rustc_serialize;

use std::fs::File;
use std::io::{BufReader};
use std::io::prelude::*;
use std::str;

use rustc_serialize::hex::{FromHex};
use cryptobuddy::{utils, freq_analysis};


fn main() {
    let f = File::open("data/4.txt").expect("Couldn't open file");
    let f = BufReader::new(f);
    let mut best_candidate: Vec<u8> = vec![];
    let mut best_word_score = 1_000_000f64;
    let mut best_candidate_index = 0;
    let mut best_candidate_key = 0;

    for (index, line) in f.lines().enumerate() {
        let foo: Vec<u8> = line.unwrap().from_hex().unwrap();

        for key in 0..128 {
            let decrypt = utils::single_byte_xor(&foo, key);
            let score = freq_analysis::text_score(&decrypt);
            if score <= best_word_score {
                best_word_score = score;
                best_candidate = decrypt.clone();
                best_candidate_index = index;
                best_candidate_key = key;
                }
            }
        }

    println!("Line Number: {}, with key \"{}\"", best_candidate_index, best_candidate_key as char);
    println!("{}", str::from_utf8(&best_candidate).unwrap());


}
