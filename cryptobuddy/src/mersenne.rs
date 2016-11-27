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
    index: usize,
}


impl Twister32 {
    pub fn new(seed: u32) -> Twister32 {
        let mut output = Twister32 {
            state_array: [0u32; N],
            index: N + 1,
        };
        output.seed(seed);
        output
    }

    pub fn from_state_array(state: &[u32]) -> Twister32 {
        debug_assert_eq!(state.len(), N);
        let mut output = Twister32 {
            state_array: [0u32; N],
            index: 0,
        };
        output.state_array.copy_from_slice(state);
        output
    }

    fn seed(&mut self, seed: u32) -> () {
        self.state_array[0] = seed;
        for x in 1..N {
            self.state_array[x] =
                F.wrapping_mul((self.state_array[x - 1] ^ (self.state_array[x - 1] >> (W - 2))) +
                               x as u32);
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            self.twist()
        }

        let mut out = self.state_array[self.index];
        out ^= (out >> U) & D;
        out ^= (out << S) & B;
        out ^= (out << T) & C;
        out ^= out >> L;

        self.index += 1;
        out

    }

    pub fn get_state_array(&self) -> [u32; N] {
        let mut output = [0u32; N];
        output.copy_from_slice(&self.state_array);
        output
    }

    fn twist(&mut self) -> () {
        for x in 0..N {
            let i = (self.state_array[x] & UPPER_MASK) +
                    (self.state_array[(x + 1) % N] & LOWER_MASK);
            let mut i_a = i >> 1;
            if i % 2 == 0 {
                i_a ^= A
            };
            self.state_array[x] = self.state_array[(x + M) % N] ^ i_a;
        }
        self.index = 0;
    }
}


pub fn untemper(output: u32) -> u32 {
    let mut o = output;
    o = invert_4(o);
    o = invert_3(o);
    o = invert_2(o);
    o = invert_1(o);
    o
}

fn invert_4(i: u32) -> u32 {
    let mut i = i;
    i ^= i >> L;
    i
}

fn invert_3(i: u32) -> u32 {
    // out ^= (out << T) & C;
    // T = 15
    let mut i = i;
    i ^= (i << T) & C;
    i
}

fn invert_2(i: u32) -> u32 {
    // out ^= (out << S) & B;
    // S = 7
    const MASK: u32 = 0b11_11111;
    let mut i = i;
    i ^= ((i << S) & B) & (MASK << 7);
    i ^= ((i << S) & B) & (MASK << 14);
    i ^= ((i << S) & B) & (MASK << 21);
    i ^= ((i << S) & B) & (MASK << 28);
    i
}

fn invert_1(i: u32) -> u32 {
    // out ^= (out >> U) & D;
    // U = 11
    const MASK: u32 = 0b11111_11111_10000_00000_00000_00000_00;
    let mut i = i;
    i ^= ((i >> U) & D) & (MASK >> 11);
    i ^= ((i >> U) & D) & (MASK >> 22);
    i
}


#[test]
fn untemper_test() {
    let mut m = Twister32::new(5000);
    let x = m.next_u32();
    let m_state = m.get_state_array();
    let x = untemper(x);
    assert_eq!(m_state[0], x);
}

#[test]
fn invert_4_test() {
    let k = 0b101010101010101010u32;
    let j = k ^ (k >> L);
    let l = invert_4(j);
    assert_eq!(k, l);
}

#[test]
fn invert_3_test() {
    let k = 0b101010101010101010u32;
    let j = k ^ ((k << T) & C);
    let l = invert_3(j);
    assert_eq!(k, l);
}

#[test]
fn invert_2_test() {
    let k = 0b101010101010101010u32;
    let j = k ^ ((k << S) & B);
    let l = invert_2(j);
    assert_eq!(k, l);
}

#[test]
fn invert_1_test() {
    let k = 0b101010101010101010u32;
    let j = k ^ ((k >> U) & D);
    let l = invert_1(j);
    assert_eq!(k, l);
}
