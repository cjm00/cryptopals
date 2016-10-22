extern crate cryptobuddy;
extern crate rand;

use cryptobuddy::{utils, crypto};

fn main() {
    let test_data: bool = rand::random();
    println!("{:?}", test_data);
}
