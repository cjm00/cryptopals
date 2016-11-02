extern crate time;
extern crate cryptobuddy;
extern crate rand;

use rand::random;
use cryptobuddy::mersenne::Twister32;

use std::time::Duration;
use std::thread::sleep;

fn main() {
    let now = time::get_time().sec as u32;
    let mut twister_original = Twister32::new(now);
    let first_output = twister_original.next();

    let wait_time = random::<u64>() % 20;
    sleep(Duration::new(wait_time, 0));

    let mut new_now = time::get_time().sec as u32;

    while Twister32::new(new_now).next() != first_output {new_now -= 1;}

    assert_eq!(now, new_now);
    println!("Cracked seed: {}", new_now);

}
