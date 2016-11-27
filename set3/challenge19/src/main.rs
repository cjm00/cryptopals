extern crate cryptobuddy;
extern crate rustc_serialize;

use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;
use std::str;

use rustc_serialize::base64::FromBase64;
use cryptobuddy::{stream, utils, freq_analysis};

static DATA_PATH: &'static str = "data/19.txt";

fn load_data() -> Vec<Vec<u8>> {
    let f = File::open(DATA_PATH).unwrap();
    let f = BufReader::new(f);
    let l: Vec<String> = f.lines().collect::<Result<Vec<_>, _>>().unwrap();
    let l: Vec<Vec<u8>> = l.into_iter().map(|x| x.from_base64().unwrap()).collect();
    l
}

fn truncate_to_shortest(vec_of_vecs: &mut Vec<Vec<u8>>) {
    let min_len = vec_of_vecs.iter().map(|s| s.len()).min().unwrap();
    for v in vec_of_vecs {
        v.truncate(min_len);
    }
}

fn transpose(vec_of_vecs: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let blocksize = vec_of_vecs[0].len();
    let mut output = Vec::<Vec<u8>>::new();
    for t in 0..blocksize {
        let block: Vec<u8> = vec_of_vecs.iter().filter_map(|s| s.get(t)).cloned().collect();
        output.push(block)
    }
    output
}

fn find_single_byte_key(data: &[u8]) -> u8 {
    let mut best_key = 0;
    let mut best_score = 1_000_000f64;
    for x in 0..255 {
        let decrypt = utils::single_byte_xor(&data, x);
        let score = freq_analysis::text_score(&decrypt);
        if score <= best_score {
            best_score = score;
            best_key = x;
        }
    }
    best_key
}
fn main() {
    let key = utils::random_key();
    let nonce = utils::u64_to_bytes(0);
    let crypter = stream::CTR::new(&key, &nonce).unwrap();
    let d = load_data();
    let mut d: Vec<Vec<u8>> = d.into_iter().map(|s| crypter.crypt(&s)).collect();
    truncate_to_shortest(&mut d);
    let d_t = transpose(&d);
    let mut key = Vec::<u8>::new();

    for block in d_t {
        key.push(find_single_byte_key(&block));
    }

    for entry in d {
        println!("{}",
                 str::from_utf8(&utils::repeating_key_xor(&entry, &key)).unwrap());
    }
}
