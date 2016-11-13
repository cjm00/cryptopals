extern crate rustc_serialize;

use rustc_serialize::base64::{ToBase64, STANDARD};
use rustc_serialize::hex::FromHex;

fn main() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let intermediate = input.from_hex().unwrap();
    let output = intermediate.to_base64(STANDARD);
    println!("{}", output);
    assert_eq!(output, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
}
