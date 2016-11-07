extern crate cryptobuddy;

use cryptobuddy::{crypto, utils};

use std::fmt::Write;
use std::str;
use std::iter;


#[derive(Debug)]
struct Profile {
    email: String,
    uid: u32,
    role: String,
}

#[derive(Debug)]
enum ProfileError {
    ParseError,
    InsufficientInfo,
}

impl Profile {
    fn for_user(email: &str) -> Profile {
        let email: String = email.replace('&', "").replace('=', "");
        Profile {
            email: email,
            uid: 10,
            role: "user".into(),
        }
    }

    fn to_cookie(&self) -> String {
        let mut output = String::new();
        write!(&mut output,
               "email={}&uid={}&role={}",
               self.email,
               self.uid,
               self.role)
            .expect("Couldn't write to cookie!");
        output
    }

    fn from_cookie(cookie: &str) -> Result<Profile, ProfileError> {
        let mut email = None;
        let mut uid = None;
        let mut role = None;

        for token in cookie.split('&') {
            let mut split_token = token.splitn(2, '=');
            match (split_token.next(), split_token.next()) {
                (None, None) => continue,
                (Some(_), None) => continue,
                (None, Some(_)) => continue,
                (Some("email"), Some(k)) => {
                    if email == None {
                        email = Some(k)
                    }
                }
                (Some("uid"), Some(k)) => {
                    if uid == None {
                        uid = Some(k)
                    }
                }
                (Some("role"), Some(k)) => {
                    if role == None {
                        role = Some(k)
                    }
                }
                (Some(_), Some(_)) => continue,
            }
        }

        if email.is_none() | uid.is_none() | role.is_none() {
            return Err(ProfileError::InsufficientInfo);
        }

        match uid.unwrap().parse::<u32>() {
            Err(_) => Err(ProfileError::ParseError),
            Ok(x) => {
                Ok(Profile {
                    email: email.unwrap().into(),
                    uid: x,
                    role: role.unwrap().into(),
                })
            }
        }
    }
}

struct EncryptionServer {
    key: [u8; 16],
}

impl EncryptionServer {
    fn new() -> EncryptionServer {
        EncryptionServer { key: utils::random_key() }
    }

    fn encrypt_cookie(&self, cookie: &str) -> Vec<u8> {
        crypto::aes_ecb_encrypt(cookie.as_bytes(), &self.key)
    }

    fn decrypt_cookie(&self, cookie: &[u8]) -> Result<Profile, ProfileError> {
        let cookie = crypto::aes_ecb_decrypt(cookie, &self.key);
        match str::from_utf8(&cookie) {
            Ok(s) => Profile::from_cookie(s),
            Err(_) => Err(ProfileError::ParseError),
        }
    }
}

fn forge_admin_block() -> Vec<u8> {
    "admin".as_bytes().iter().cloned().chain(iter::repeat(11u8)).take(16).collect()
}

fn forge_email_string_with_offset() -> String {
    String::from_utf8(iter::repeat(b'A')
            .take(10)
            .chain(forge_admin_block().iter().cloned())
            .collect::<Vec<u8>>())
        .unwrap()
}

fn main() {
    let server = EncryptionServer::new();

    let bogus_email = forge_email_string_with_offset();
    let bogus_profile = Profile::for_user(bogus_email.as_str());
    let bogus_encrypted = server.encrypt_cookie(bogus_profile.to_cookie().as_str());
    let lifted_admin_block = &bogus_encrypted[16..32];

    let legit_profile = Profile::for_user("hackr@aol.com");
    let legit_enc = server.encrypt_cookie(legit_profile.to_cookie().as_str());

    let doctored_encrypted_profile: Vec<u8> = legit_enc[..legit_enc.len() - 16]
        .iter()
        .cloned()
        .chain(lifted_admin_block.iter().cloned())
        .collect();
    let doctored_profile = server.decrypt_cookie(&doctored_encrypted_profile);

    println!("{:?}", doctored_profile.unwrap());

}
