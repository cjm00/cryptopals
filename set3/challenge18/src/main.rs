extern crate cryptobuddy;
extern crate rustc_serialize;

use std::str;

use rustc_serialize::base64::FromBase64;
use cryptobuddy::{stream, utils};

static KEY: &'static str = "YELLOW SUBMARINE";
static MESSAGE: &'static str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

fn main() {
    let message = MESSAGE.from_base64().unwrap();
    let nonce = utils::u64_to_bytes(0u64);
    let c = stream::CTR::new(&KEY, &nonce).unwrap();
    let s = c.crypt(&message);
    println!("{:?}", str::from_utf8(&s).unwrap());
}
