const W: u32 = 32;               // word size
const N: usize = 624;            // Degree of recurrence
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908B0DF;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;
const F: u32 = 1812433253;
const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct Twister32 {
    state_array: [u32; N],
    index: usize
}

impl Twister32 {
    pub fn new(seed: u32) -> Twister32 {
        let mut output = Twister32{state_array: [0u32; N], index: N+1};
        output.seed(seed);
        output
    }

    fn seed(&mut self, seed: u32) -> () {
        self.state_array[0] = seed;
        for x in 1..N {
            self.state_array[x] = F.wrapping_mul((self.state_array[x-1] ^ (self.state_array[x-1] >> (W - 2))) + x as u32);
        }
    }

    pub fn next(&mut self) -> u32 {
        if self.index >= N {self.twist()}

        let mut out = self.state_array[self.index];
        out ^= (out >> U) & D;
        out ^= (out << S) & B;
        out ^= (out << T) & C;
        out ^= out >> L;

        self.index += 1;
        out

    }

    fn twist(&mut self) -> () {
        for x in 0..N {
            let i = (self.state_array[x] & UPPER_MASK) + (self.state_array[(x+1) % N] & LOWER_MASK);
            let mut i_a = i >> 1;
            if i % 2 == 0 {i_a ^= A};
            self.state_array[x] = self.state_array[(x+M) % N] ^ i_a;
        }
        self.index = 0;
    }
}
