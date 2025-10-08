use ml_dsa::{EncodedSignature, EncodedSigningKey, KeyGen, MlDsa87, Signature, SigningKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MlDsaKeypair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
pub struct MlDsa;

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

#[wasm_bindgen]
impl MlDsa {
    fn keygen_random() -> MlDsaKeypair {
        let mut rng = rand::rngs::OsRng;

        let keypair = MlDsa87::key_gen(&mut rng);

        MlDsaKeypair {
            public_key: keypair.verifying_key().encode().to_vec(),
            private_key: keypair.signing_key().encode().to_vec(),
        }
    }

    fn keygen_deterministic(seed: &[u8]) -> Result<MlDsaKeypair, String> {
        if seed.len() != 32 {
            return Err("The seed is expected to be exactly 32 bytes".into());
        }

        let seed = ml_dsa::B32::try_from(&seed[0..32]).map_err(|e| format!("Could not build seed: {e}"))?;
        let keypair = MlDsa87::key_gen_internal(&seed);

        Ok(MlDsaKeypair {
            public_key: keypair.verifying_key().encode().to_vec(),
            private_key: keypair.signing_key().encode().to_vec(),
        })
    }

    /// Generates a verifying (public), and a corresponding signing (private)
    /// [ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) key.
    ///
    /// This function takes in an optional seed of **exactly** 32 bytes, which
    /// can be used to generate a key pair deterministically.
    /// [ML-DSA.KeyGen_internal](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#algorithm.6)
    /// algorithm.
    ///
    /// If no seed is passed, `KeyGen` will generate the key pair randomly, as specified in the
    /// [ML-KEM.KeyGen](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#algorithm.1)
    /// algorithm.
    #[wasm_bindgen(js_name = "KeyGen")]
    pub fn keygen_internal(seed: Option<Vec<u8>>) -> Result<MlDsaKeypair, String> {
        match seed {
            Some(seed) => Self::keygen_deterministic(seed.as_slice()),
            None => Ok(Self::keygen_random()),
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
    #[wasm_bindgen(js_name = "Sign")]
    pub fn sign(#[wasm_bindgen(js_name = "privateKey")] private_key: &[u8], message: &[u8], context: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
        let mut rng = rand::rngs::OsRng;
        let private_key =
            EncodedSigningKey::<MlDsa87>::try_from(private_key).map_err(|e| format!("Could not get encoded signing key from private_key: {e}"))?;

        let context = context.unwrap_or_default();

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
    #[wasm_bindgen(js_name = "Verify")]
    pub fn verify(
        #[wasm_bindgen(js_name = "publicKey")] public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        context: Option<Vec<u8>>,
    ) -> Result<bool, String> {
        let encoded_public_key = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key).map_err(|e| format!("Could not encode verifying key: {e}"))?;
        let public_key = ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded_public_key);
        let encoded_signature = EncodedSignature::<MlDsa87>::try_from(signature).map_err(|e| format!("Could not encode signature: {e}"))?;

        let context = context.unwrap_or_default();

        match Signature::<MlDsa87>::decode(&encoded_signature) {
            Some(sigma) => Ok(public_key.verify_with_context(message, &context, &sigma)),
            None => Err("Could not decode signature".to_string()),
        }
    }
}
