extern crate cryptobuddy;

use cryptobuddy::pkcs7;


static SECRET_KEY: &'static str = "YELLOW SUBMARINE";


fn main() {
    let test_block: Vec<u8> = SECRET_KEY.into();
    let output_block = pkcs7::pad(&test_block, 20);
    println!("{:?}", output_block);
    println!("{}", output_block.len());
}
