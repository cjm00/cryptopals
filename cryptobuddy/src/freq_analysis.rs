use utils::*;
use std::str;
use std::f64;
use std::ascii::AsciiExt;

const TABLE_LENGTH: usize = 27;

static ENG_FREQ: [f64; TABLE_LENGTH] =
    [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015 /* A-G */, 0.06094,
     0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749 /* H-N */, 0.07507, 0.01929,
     0.00095, 0.05987, 0.06327, 0.09056, 0.02758 /* O-U */, 0.00978, 0.02360, 0.00150,
     0.01974, 0.00074, 0.1 /* V-Z, whitespace */];


#[derive(Debug)]
pub struct CharacterCounter {
    chars: [usize; 27],
}

impl CharacterCounter {
    pub fn from<I: Iterator<Item = char>> (x: I) -> CharacterCounter {
        let mut out = CharacterCounter { chars: [0usize; TABLE_LENGTH] };
        for item in x {
            match item {
                'a' | 'A' => out.chars[0] += 1,
                'b' | 'B' => out.chars[1] += 1,
                'c' | 'C' => out.chars[2] += 1,
                'd' | 'D' => out.chars[3] += 1,
                'e' | 'E' => out.chars[4] += 1,
                'f' | 'F' => out.chars[5] += 1,
                'g' | 'G' => out.chars[6] += 1,
                'h' | 'H' => out.chars[7] += 1,
                'i' | 'I' => out.chars[8] += 1,
                'j' | 'J' => out.chars[9] += 1,
                'k' | 'K' => out.chars[10] += 1,
                'l' | 'L' => out.chars[11] += 1,
                'm' | 'M' => out.chars[12] += 1,
                'n' | 'N' => out.chars[13] += 1,
                'o' | 'O' => out.chars[14] += 1,
                'p' | 'P' => out.chars[15] += 1,
                'q' | 'Q' => out.chars[16] += 1,
                'r' | 'R' => out.chars[17] += 1,
                's' | 'S' => out.chars[18] += 1,
                't' | 'T' => out.chars[19] += 1,
                'u' | 'U' => out.chars[20] += 1,
                'v' | 'V' => out.chars[21] += 1,
                'w' | 'W' => out.chars[22] += 1,
                'x' | 'X' => out.chars[23] += 1,
                'y' | 'Y' => out.chars[24] += 1,
                'z' | 'Z' => out.chars[25] += 1,
                _ => out.chars[26] += 1,
            }
        }

        out
    }

    pub fn total(&self) -> usize {
        let mut out = 0usize;
        for k in &self.chars {
            out += *k;
        }

        out
    }
}

#[derive(Debug)]
pub struct CharacterFreq {
    char_freqs: [f64; TABLE_LENGTH],
    cardinality: usize,
}

impl CharacterFreq {
    pub fn from_count(x: CharacterCounter) -> CharacterFreq {
        let mut out = CharacterFreq {
            char_freqs: [0f64; TABLE_LENGTH],
            cardinality: x.total(),
        };
        let char_count = x.total();
        assert!(char_count != 0);
        for k in 0..TABLE_LENGTH {
            out.char_freqs[k] = int_div(x.chars[k], char_count);
        }

        out
    }

    fn chi_squared_test(&self) -> f64 {
        let mut out = 0f64;
        for k in 0..TABLE_LENGTH {
            out += (self.char_freqs[k] - ENG_FREQ[k]).powi(2) / ENG_FREQ[k]
        }

        out * (self.cardinality as f64)
    }
}

fn chi_squared_eval(s: &str) -> f64 {
    if !s.is_ascii() {
        return f64::INFINITY;
    }
    let counts = CharacterCounter::from(s.chars());
    let freqs = CharacterFreq::from_count(counts);
    freqs.chi_squared_test()
}

pub fn text_score(input: &[u8]) -> f64 {
    if input.iter()
        .any(|&x| ((x < 32) && (x as char) != '\t' && (x as char) != '\n') || (x >= 127)) {
        return f64::INFINITY;
    }

    match str::from_utf8(input) {
        Err(_) => f64::INFINITY,
        Ok(s) => chi_squared_eval(s),
    }

}
