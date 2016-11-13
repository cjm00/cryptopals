extern crate rustc_serialize;
extern crate cryptobuddy;

use std::fs::File;
use std::io::{BufReader};
use std::io::prelude::*;
use std::str;

use rustc_serialize::base64::{FromBase64};
use cryptobuddy::utils;



fn main() {
    let f = File::open("data/8.txt").expect("Couldn't open file");
    let f = BufReader::new(f);

    for (index, line) in f.lines().enumerate() {
        let line = line.unwrap().from_base64().unwrap();
        if utils::detect_repeated_blocks(&line, 16) {println!("Line {} has repeated blocks.", index);}
    }
}
