extern crate cryptobuddy;
extern crate rustc_serialize;

use rustc_serialize::hex::{FromHex, ToHex};
use cryptobuddy::crypto::fixed_xor;


fn main() {
    let input1 = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let input2 = "686974207468652062756c6c277320657965".from_hex().unwrap();
    let output = fixed_xor(&input1, &input2);

    println!("{}", output.to_hex());
    assert_eq!("746865206b696420646f6e277420706c6179", output.to_hex())
}
