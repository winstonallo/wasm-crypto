use sha3::{Digest, Sha3_512 as sha3_512};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Sha3_512;

#[wasm_bindgen]
impl Sha3_512 {
    /// Computes a SHA-3-512 hash of the input data.
    ///
    /// SHA-3 (Secure Hash Algorithm 3) is a cryptographic hash function standardized by NIST
    /// in FIPS 202. SHA-3-512 produces a 512-bit (64-byte) hash digest.
    ///
    /// # References
    ///
    /// * [NIST FIPS 202: SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final)
    /// * [SHA-3 on Wikipedia](https://en.wikipedia.org/wiki/SHA-3)
    #[wasm_bindgen(js_name = "sha3Hash512")]
    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = sha3_512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}
