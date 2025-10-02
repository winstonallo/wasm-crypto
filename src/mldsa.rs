use ml_dsa::{EncodedSignature, EncodedSigningKey, KeyGen, MlDsa87, Signature, SigningKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MlDsaKeypair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl MlDsaKeypair {
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_owned()
    }

    #[wasm_bindgen(getter, js_name = "privateKey")]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.to_owned()
    }
}

/// Generates a verifying (public), and a corresponding signing (private)
/// [ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) key.
#[wasm_bindgen(js_name = "mldsaKeygen")]
pub fn keygen() -> MlDsaKeypair {
    let mut rng = rand::rngs::OsRng;
    let keypair = MlDsa87::key_gen(&mut rng);
    let public_key = keypair.verifying_key().clone();
    let private_key = keypair.signing_key().clone();

    MlDsaKeypair {
        public_key: public_key.encode().to_vec(),
        private_key: private_key.encode().to_vec(),
    }
}

/// The signing algorithm [ML-DSA.Sign](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#algorithm.2)
/// takes a signing (private) key, a message, and a context string as an input.
///
/// This function implements the default "hedged" version of ML-DSA signing, it uses randomness internally to generate
/// a 256-bit random seed. This makes the signatures non-deterministic, and safer against side-channel attacks.
///
/// ### Parameters
/// * `private_key`: Signing key generated with `mldsaKeygen`
/// * `message`: Message that is to be signed
/// * `context`: Optional context string (up to 255 bytes), treated as an empty string if omitted
#[wasm_bindgen(js_name = "mldsaSign")]
pub fn sign(
    #[wasm_bindgen(js_name = "privateKey")] private_key: &[u8],
    message: &[u8],
    context: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let mut rng = rand::rngs::OsRng;
    let private_key = EncodedSigningKey::<MlDsa87>::try_from(private_key)
        .map_err(|e| format!("Could not get encoded signing key from private_key: {e}"))?;

    let context = if context.is_none() {
        b"".to_vec()
    } else {
        context.unwrap()
    };

    let signature = SigningKey::<MlDsa87>::decode(&private_key)
        .sign_randomized(message, &context, &mut rng)
        .unwrap()
        .encode();

    Ok(signature.to_vec())
}

/// The verification algorithm [ML-DSA.Verify](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#algorithm.3)
/// takes a verifying (public) key, signature, and a context string as input. This function returns `true` if the signature
/// is valid with respect to the message, context, and public key, and `false` if the signature is invalid.
///
/// ### Parameters
/// * `public_key`: Signing key generated with `mldsaKeygen`
/// * `message`: Signed message
/// * `signature`: The signature that is to be verified
/// * `context`: Optional context string (up to 255 bytes), treated as an empty string if omitted
#[wasm_bindgen(js_name = "mldsaVerify")]
pub fn verify(
    #[wasm_bindgen(js_name = "publicKey")] public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: Option<Vec<u8>>,
) -> Result<bool, String> {
    let encoded_public_key = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
        .map_err(|e| format!("Could not encode verifying key: {e}"))?;
    let public_key = ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded_public_key);
    let encoded_signature = EncodedSignature::<MlDsa87>::try_from(signature)
        .map_err(|e| format!("Could not encode signature: {e}"))?;

    let context = if context.is_none() {
        Vec::new()
    } else {
        context.unwrap()
    };

    match Signature::<MlDsa87>::decode(&encoded_signature) {
        Some(sigma) => Ok(public_key.verify_with_context(message, &context, &sigma)),
        None => Err("Could not decode signature".to_string()),
    }
}
