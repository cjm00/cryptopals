extern crate cryptobuddy;

use cryptobuddy::mersenne;

fn main() {
    let mut rng = mersenne::Twister32::new(76548247);
    println!("{}", rng.next());
    println!("{}", rng.next());
    println!("{}", rng.next());
    println!("{}", rng.next());
}
