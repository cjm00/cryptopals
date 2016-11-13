extern crate cryptobuddy;
extern crate rustc_serialize;

use rustc_serialize::hex::{ToHex};
use cryptobuddy::utils;


fn main() {
    let target = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";

    let target_bytes: Vec<u8> = target.into();
    let key_bytes: Vec<u8> = key.into();

    let output = utils::repeating_key_xor(&target_bytes, &key_bytes);
    println!("{}", output.to_hex());
    assert_eq!(output.to_hex(), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d\
                                 623d63343c2a26226324272765272a282b2f20430a652e\
                                 2c652a3124333a653e2b2027630c692b20283165286326\
                                 302e27282f")
}
