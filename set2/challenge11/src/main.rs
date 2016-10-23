extern crate cryptobuddy;
extern crate rand;

use cryptobuddy::{utils, crypto};


fn main() {
    let test_data: Vec<u8> = vec![1, 2, 3];
    let test_data = utils::pad_both_sides(&test_data);
    println!("{:?}", test_data);
}
