extern crate cryptobuddy;
extern crate rand;

use cryptobuddy::mersenne::{Twister32, untemper};
use rand::random;


fn main() {
    let seed: u32 = random();
    let mut t = Twister32::new(seed);

    let mut values = [0u32; 624];

    for x in 0..624 {
        values[x] = untemper(t.next_u32());
    }

    let mut t_cloned = Twister32::from_state_array(&values);

    for _ in 0..624 {
        let _ = t_cloned.next_u32();
    }

    for _ in 0..100 {
        assert_eq!(t_cloned.next_u32(), t.next_u32());
    }

    println!("Successfully cloned.");
}
