extern crate cryptobuddy;
extern crate rustc_serialize;
extern crate ordered_float;

use std::fs::File;
use std::io::prelude::*;
use std::str;

use rustc_serialize::base64::FromBase64;
use cryptobuddy::{crypto, freq_analysis, utils};
use ordered_float::NotNaN;

const MAX_KEYSIZE: usize = 40;

fn load_data() -> Vec<u8> {
    let mut f = File::open("data/6.txt").expect("Couldn't open file");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("File didn't go so well.");
    s.from_base64().unwrap()
}

fn split_and_ham(x: &[u8]) -> f64 {
    let (a, b) = x.split_at(x.len() / 2);
    utils::normalized_hamming_distance(&a, &b)
}

fn key_size_likelihood(input: &[u8], key_size: usize) -> f64 {
    const NUM_SAMPLES: usize = 16;
    let batch_scores: Vec<f64> = input.chunks(key_size * 2)
        .map(split_and_ham)
        .take(NUM_SAMPLES)
        .collect();
    batch_scores.iter().fold(0f64, |acc, x| acc + x) / batch_scores.len() as f64
}

fn estimate_key_size(data: &[u8]) -> usize {
    let mut key_weights = vec![];
    for t in 2..MAX_KEYSIZE {
        match NotNaN::new(key_size_likelihood(&data, t)) {
            Ok(s) => key_weights.push((t, s)),
            _ => continue,
        }
    }

    key_weights.sort_by_key(|k| k.1);
    key_weights.iter().map(|&(i, _)| i).nth(0).unwrap()
}

fn transpose_blocks(data: &[u8], blocksize: usize) -> Vec<Vec<u8>> {
    let mut out = vec![];
    for k in 0..blocksize {
        let block: Vec<u8> = data.chunks(blocksize).filter_map(|s| s.get(k)).cloned().collect();
        out.push(block)
    }
    out
}

fn find_single_byte_key(data: &[u8]) -> u8 {
    let mut best_key = 0;
    let mut best_score = 1_000_000f64;
    for x in 0..255 {
        let decrypt = crypto::single_byte_xor(&data, x);
        let score = freq_analysis::text_score(&decrypt);
        if score <= best_score {
            best_score = score;
            best_key = x;
        }
    }
    best_key
}

fn main() {
    let data = load_data();
    let potential_key_size = estimate_key_size(&data);


    let test_blocks = transpose_blocks(&data, potential_key_size);
    let mut key = Vec::<u8>::new();

    for block in test_blocks {
        key.push(find_single_byte_key(&block));
    }
    println!("{}",
             str::from_utf8(&crypto::repeating_key_xor(&data, &key)).unwrap());
    println!("Key = \"{}\"", str::from_utf8(&key).unwrap());


}
