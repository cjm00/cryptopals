use std::iter;



#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PaddingError {
    EmptyInput,
    InvalidPadding,
}


pub fn pad(block: &[u8], block_size: usize) -> Vec<u8> {
    if (block.len() % block_size) == 0 {
        block.iter()
            .cloned()
            .chain(iter::repeat(block_size as u8).take(block_size))
            .collect()
    } else {
        let residue: u8 = (block.len() % block_size) as u8;
        block.iter()
            .cloned()
            .chain(iter::repeat(block_size as u8 - residue).take(block_size - residue as usize))
            .collect()

    }
}


pub fn pad_size(data: &[u8]) -> Result<usize, PaddingError> {
    use self::PaddingError::{EmptyInput, InvalidPadding};
    match data.iter().last() {
        None => Err(EmptyInput),
        Some(&0) => Err(InvalidPadding),
        Some(&u) => {
            if data.iter()
                .rev()
                .take(u as usize)
                .all(|&z| z == u) {
                Ok(u as usize)
            } else {
                Err(InvalidPadding)
            }
        }
    }
}


pub fn trim(data: &mut Vec<u8>) -> Result<(), PaddingError> {
    let data_len = data.len(); // Non-lexical borrows pls
    match pad_size(data) {
        Err(t) => Err(t),
        Ok(u) => Ok(data.truncate(data_len - u)),
    }

}

#[cfg(test)]
mod pkcs7_tests {
    use super::*;
    #[test]
    fn pad_test_1() {
        let block = vec![5; 5];
        let block = pad(&block, 16);
        let output = vec![5, 5, 5, 5, 5, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
        assert_eq!(block, output);
    }

    #[test]
    fn valid_pad_size_test() {
        let block = vec![5, 5, 5, 5, 5, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
        let pad = pad_size(&block);
        assert_eq!(pad, Ok(11));
    }

    #[test]
    fn invalid_pad_size_test() {
        let block = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let pad = pad_size(&block);
        assert_eq!(pad, Err(PaddingError::InvalidPadding));
    }

    #[test]
    fn empty_pad_size_test() {
        let block = vec![];
        let pad = pad_size(&block);
        assert_eq!(pad, Err(PaddingError::EmptyInput));

    }
}
