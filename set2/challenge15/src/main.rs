extern crate cryptobuddy;

use cryptobuddy::crypto;

fn main() {
    let mut ice1: Vec<u8> = "ICE ICE BABY\x04\x04\x04\x04".into();
    let mut ice2: Vec<u8> = "ICE ICE BABY\x05\x05\x05\x05".into();
    let mut ice3: Vec<u8> = "ICE ICE BABY\x01\x02\x03\x04".into();
    println!("{:?}", crypto::trim_padding(&mut ice1));
    println!("{:?}", crypto::trim_padding(&mut ice2));
    println!("{:?}", crypto::trim_padding(&mut ice3));
}
