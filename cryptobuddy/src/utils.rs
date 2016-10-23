use rand::{Rng, thread_rng, random};

pub fn int_div(a: usize, b: usize) -> f64 {
    a as f64 / b as f64
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x ^ y)
        .map(|z| z.count_ones() as usize)
        .fold(0, |acc, x| acc + x)
}

pub fn normalized_hamming_distance(a: &[u8], b: &[u8]) -> f64 {
    int_div(hamming_distance(a, b), a.len())
}

pub fn random_key() -> [u8; 16] {
    random()
}

pub fn pad_both_sides(data: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let front_size: usize = rng.gen_range(5, 11);
    let back_size: usize = rng.gen_range(5, 11);

    let mut output = Vec::<u8>::new();
    output.extend(rng.gen_iter::<u8>().take(front_size));
    output.extend_from_slice(data);
    output.extend(rng.gen_iter::<u8>().take(back_size));
    output
}
