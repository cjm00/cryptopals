use std::env;


fn main() {
    // These environment variables need to be set on windows for the Rust OpenSSL bindings to compile
    // https://github.com/sfackler/rust-openssl/issues/418
    if cfg!(target_os = "windows") {
        env::set_var("DEP_OPENSSL_INCLUDE", "C:/OpenSSL-Win64/include");
        env::set_var("OPENSSL_INCLUDE_DIR", "C:/OpenSSL-Win64/include");
        env::set_var("OPENSSL_LIB_DIR", "C:/OpenSSL-Win64/lib/VC");
        env::set_var("OPENSSL_LIBS", "ssleay32MT:libeay32MT");

    }
}
