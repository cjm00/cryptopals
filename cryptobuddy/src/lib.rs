extern crate crypto as rust_crypto;
extern crate rand;


pub mod freq_analysis;
pub mod crypto;
pub mod utils;
pub mod mersenne;



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

#[cfg(test)]
mod crypto_tests {
    use crypto;
    use std::iter;
    #[test]
    fn aes_cbc_test() {
        let iv: Vec<u8> = iter::repeat(2u8).take(16).collect();
        let key: Vec<u8> = "YELLOW SUBMARINE".into();
        let test_data: Vec<u8> = "THIS IS A TEST OF CBCTHIS IS A TEST OF CBC".into();
        let encrypt_test_data = crypto::aes_cbc_encrypt(&test_data, &key, &iv);
        let decrypt_test_data = crypto::aes_cbc_decrypt(&encrypt_test_data, &key, &iv);
        assert_eq!(test_data, decrypt_test_data);
    }
}
