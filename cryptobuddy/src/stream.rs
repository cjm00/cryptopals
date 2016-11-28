use block;
use utils;
use mersenne::Twister32;

#[derive(Clone, Debug)]
pub enum CTRConstructionError {
    InvalidKeySize,
    InvalidNonceSize,
}

#[derive(Clone, Debug)]
pub struct CTR {
    key: [u8; 16],
    nonce: [u8; 8],
}

impl CTR {
    pub fn new<T: AsRef<[u8]>, U: AsRef<[u8]>>(input_key: &T,
                                               input_nonce: &U)
                                               -> Result<CTR, CTRConstructionError> {
        use self::CTRConstructionError::*;

        let mut key = [0u8; 16];
        let mut nonce = [0u8; 8];

        match input_key.as_ref().len() {
            16 => key.copy_from_slice(&input_key.as_ref()),
            _ => return Err(InvalidKeySize),

        }

        match input_nonce.as_ref().len() {
            8 => nonce.copy_from_slice(&input_nonce.as_ref()),
            _ => return Err(InvalidNonceSize),
        }

        Ok(CTR {
            key: key,
            nonce: nonce,
        })
    }

    pub fn iter(&self) -> CTRIterator {
        CTRIterator {
            ctr: &self,
            counter: 0u64,
            buffer: [0; 16],
            buffer_index: None,
        }
    }

    pub fn crypt(&self, target: &[u8]) -> Vec<u8> {
        target.iter().cloned().zip(self.iter()).map(|(x, y)| x ^ y).collect()
    }
}

pub struct CTRIterator<'a> {
    ctr: &'a CTR,
    counter: u64,
    buffer: [u8; 16],
    buffer_index: Option<usize>,
}

impl<'a> CTRIterator<'a> {
    fn populate_buffer(&mut self) {
        let mut v = [0u8; 16];
        v[..8].copy_from_slice(&self.ctr.nonce);
        v[8..].copy_from_slice(&utils::u64_to_bytes(self.counter));
        self.buffer.copy_from_slice(&block::aes_ecb_encrypt_raw(&v, &self.ctr.key))
    }
}

impl<'a> Iterator for CTRIterator<'a> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        match self.buffer_index {
            None => {
                self.buffer_index = Some(1);
                self.populate_buffer();
                Some(self.buffer[0])
            }
            Some(u) if u < 16 => {
                self.buffer_index = Some(u + 1);
                Some(self.buffer[u])
            }
            Some(_) => {
                self.counter += 1;
                self.populate_buffer();
                self.buffer_index = Some(1);
                Some(self.buffer[0])
            }
        }
    }
}

pub struct MTStream {
    seed: u32,
}

impl MTStream {
    pub fn new<T: Into<u32>>(seed: T) -> MTStream {
        MTStream{seed: seed.into()}
    }

    pub fn iter(&self) -> MTStreamIter {
        MTStreamIter {
            twister: Twister32::new(self.seed as u32),
            buffer: [0; 4],
            buffer_index: None,
        }
    }

    pub fn crypt(&self, target: &[u8]) -> Vec<u8> {
        target.iter().cloned().zip(self.iter()).map(|(x, y)| x ^ y).collect()
    }
}

pub struct MTStreamIter {
    twister: Twister32,
    buffer: [u8; 4],
    buffer_index: Option<usize>,
}

impl MTStreamIter {
    fn populate_buffer(&mut self) {
        self.buffer.copy_from_slice(&utils::u32_to_bytes(self.twister.next_u32()));
    }
}

impl Iterator for MTStreamIter {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        match self.buffer_index {
            None => {
                self.buffer_index = Some(1);
                self.populate_buffer();
                Some(self.buffer[0])
            }
            Some(u) if u < 4 => {
                self.buffer_index = Some(u + 1);
                Some(self.buffer[u])
            }
            Some(_) => {
                self.populate_buffer();
                self.buffer_index = Some(1);
                Some(self.buffer[0])
            }
        }
    }
}


#[test]
fn test_MTStreamCrypt() {
    let plaintext: Vec<u8> = "BANANAS APPLES GRAPES ORANGES BLUEBERRIES".into();
    let crypter = MTStream::new(500);
    let ciphertext = crypter.crypt(&plaintext);
    let decipher_text = crypter.crypt(&ciphertext);
    assert_eq!(plaintext, decipher_text);
}
