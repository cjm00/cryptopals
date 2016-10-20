extern crate cryptobuddy;

use cryptobuddy::utils;

fn main() {
    let test_data = utils::random_key();
    println!("{:?}", test_data);
}
