extern crate cryptobuddy;
extern crate rustc_serialize;

use std::fs::File;
use std::io::prelude::*;
use std::iter;
use std::str;

use rustc_serialize::base64::{FromBase64};
use cryptobuddy::crypto;


fn load_data () -> Vec<u8> {
    let mut f = File::open("data/10.txt").expect("Couldn't open file");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("File didn't go so well.");
    let s = s.from_base64().unwrap();
    s
}

fn main() {
    let data: Vec<u8> = load_data();
    let iv: Vec<u8> = iter::repeat(0u8).take(16).collect();
    let key: Vec<u8> = "YELLOW SUBMARINE".into();
    let decrypt_data = crypto::aes_cbc_decrypt(&data, &key, &iv);
    println!("{}", str::from_utf8(&decrypt_data).unwrap());

}
