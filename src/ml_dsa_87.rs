use ml_dsa::{
    EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa87, Signature,
    SigningKey, VerifyingKey, signature::SignerMut,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MlDsa {
    verifying_key: VerifyingKey<MlDsa87>,
    signing_key: SigningKey<MlDsa87>,
}

#[wasm_bindgen]
impl MlDsa {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let keypair = MlDsa87::key_gen(&mut rng);
        Self {
            verifying_key: keypair.verifying_key().clone(),
            signing_key: keypair.signing_key().clone(),
        }
    }

    #[wasm_bindgen(getter, js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.verifying_key.encode().to_vec()
    }

    #[wasm_bindgen(getter, js_name = "signingKey")]
    pub fn signing_key(&self) -> Vec<u8> {
        self.signing_key.encode().to_vec()
    }

    #[wasm_bindgen]
    pub fn decode(verifying_key: &[u8], signing_key: &[u8]) -> Result<Self, String> {
        let encoded_verifying_key = EncodedVerifyingKey::<MlDsa87>::try_from(verifying_key)
            .map_err(|e| format!("Could not get encoded verifying key from verifying_key: {e}"))?;
        let encoded_signing_key = EncodedSigningKey::<MlDsa87>::try_from(signing_key)
            .map_err(|e| format!("Could not get encoded signing key from signing_key: {e}"))?;

        let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_verifying_key);
        let signing_key = SigningKey::<MlDsa87>::decode(&encoded_signing_key);

        Ok(Self {
            verifying_key,
            signing_key,
        })
    }

    #[wasm_bindgen]
    pub fn sign(signing_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        let encoded_signing_key = EncodedSigningKey::<MlDsa87>::try_from(signing_key)
            .map_err(|e| format!("Could not get encoded signing key from signing_key: {e}"))?;

        let mut signing_key = SigningKey::<MlDsa87>::decode(&encoded_signing_key);
        Ok(signing_key.sign(msg).encode().to_vec())
    }

    pub fn verify(msg: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String> {
        Self::verify_static_with_context(msg, &[], signature, public_key)
    }

    fn verify_static_with_context(
        msg: &[u8],
        ctx: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, String> {
        let encoded_pk = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key) {
            Ok(encoded) => encoded,
            Err(e) => return Err(format!("Could not encode public key: {e}")),
        };

        let verifying_key = ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded_pk);

        let encoded_sig = match EncodedSignature::<MlDsa87>::try_from(signature) {
            Ok(encoded) => encoded,
            Err(e) => return Err(format!("Could not encode signature: {e}")),
        };

        match Signature::<MlDsa87>::decode(&encoded_sig) {
            Some(sigma) => Ok(verifying_key.verify_with_context(msg, ctx, &sigma)),
            None => Err("Could not decode signature".to_string()),
        }
    }
}
