extern crate cryptobuddy;
extern crate rustc_serialize;

use std::fs::File;
use std::io::prelude::*;
use std::str;

use rustc_serialize::base64::{FromBase64};
use cryptobuddy::block;

static SECRET_KEY: &'static str = "YELLOW SUBMARINE";

fn load_data () -> Vec<u8> {
    let mut f = File::open("data/7.txt").expect("Couldn't open file");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("File didn't go so well.");
    let s = s.from_base64().unwrap();
    s
}

fn main() {
    let data = load_data();
    let key: Vec<u8> = SECRET_KEY.into();
    let output = block::aes_ecb_decrypt(&data, &key);
    println!("{}", str::from_utf8(&output).unwrap());
}
