use rand;

pub fn int_div(a: usize, b: usize) -> f64 {
    a as f64 / b as f64
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter())
            .map( |(x, y)| x ^ y)
            .map( |z| z.count_ones() as usize)
            .fold(0, |acc, x| acc + x)
}

pub fn normalized_hamming_distance(a: &[u8], b: &[u8]) -> f64 {
    int_div(hamming_distance(&a, &b), a.len())
}

pub fn random_key () -> [u8; 16] {
    let output: [u8; 16] = rand::random();
    output
}
