use std::iter;

#[derive(Debug, Copy, Clone)]
pub enum PaddingError{
    EmptyInput,
    InvalidPadding
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
    match data.iter().cloned().last() {
        None => Err(EmptyInput),
        Some(0) => {
            if data.iter()
                .cloned()
                .rev()
                .take(16)
                .all(|z| z == 0) {
                Ok(16)
            } else {
                Err(InvalidPadding)
            }
        }
        Some(u) => {
            if data.iter()
                .cloned()
                .rev()
                .take(u as usize)
                .all(|z| z == u) {
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
