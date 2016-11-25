use rand::{Rng, thread_rng, random};

use std::iter;
use std::mem::transmute;

pub fn fixed_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x ^ y)
        .collect()
}


pub fn single_byte_xor(stream: &[u8], key: u8) -> Vec<u8> {
    let key_stream: Vec<u8> = iter::repeat(key).take(stream.len()).collect();
    fixed_xor(stream, &key_stream)
}


pub fn repeating_key_xor(stream: &[u8], key: &[u8]) -> Vec<u8> {
    let key_stream: Vec<u8> = key.iter().cloned().cycle().take(stream.len()).collect();
    fixed_xor(stream, &key_stream)
}


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


pub fn detect_repeated_blocks(stream: &[u8], block_size: usize) -> bool {
    for (index, block) in stream.chunks(block_size).enumerate() {
        if stream.chunks(block_size).skip(index + 1).any(|z| z == block) {
            return true;
        }
    }
    false
}

pub fn u64_to_bytes(u: u64) -> [u8; 8] {
    let output: [u8; 8] = unsafe { transmute(u.to_le()) };
    output
}


#[cfg(test)]
mod utils_tests {
    use utils;
    #[test]
    fn hamming_distance_test() {
        let a: Vec<u8> = "this is a test".into();
        let b: Vec<u8> = "wokka wokka!!!".into();
        assert_eq!(37, utils::hamming_distance(&a, &b))
    }
}
