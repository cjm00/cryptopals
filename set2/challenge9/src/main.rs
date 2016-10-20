extern crate cryptobuddy;

use cryptobuddy::crypto;


static SECRET_KEY: &'static str = "YELLOW SUBMARINE";


fn main() {
    let test_block: Vec<u8> = SECRET_KEY.into();
    let output_block = crypto::pkcs7_pad(&test_block, 20);
    println!("{:?}", output_block);
    println!("{}", output_block.len());
}
