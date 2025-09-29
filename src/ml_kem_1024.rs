use ml_kem::{
    Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MlKem {
    decapsulation_key: DecapsulationKey<MlKem1024Params>,
    encapsulation_key: EncapsulationKey<MlKem1024Params>,
}

#[wasm_bindgen]
pub struct MlKemEncapsulation {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemEncapsulation {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter, js_name = "sharedSecret")]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

#[wasm_bindgen]
impl MlKem {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let (decapsulation_key, encapsulation_key) = MlKem1024::generate(&mut rng);
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    #[wasm_bindgen]
    pub fn decode(encapsulation_key: &[u8], decapsulation_key: &[u8]) -> Result<Self, String> {
        let encoded_enc_key =
            Encoded::<EncapsulationKey<MlKem1024Params>>::try_from(encapsulation_key)
                .map_err(|e| format!("Could not get encoded encapsulation key from bytes: {e}"))?;

        let encapsulation_key = EncapsulationKey::<MlKem1024Params>::from_bytes(&encoded_enc_key);

        let encoded_dec_key =
            Encoded::<DecapsulationKey<MlKem1024Params>>::try_from(decapsulation_key)
                .map_err(|e| format!("Could not get encoded decapsulation key from bytes: {e}"))?;

        let decapsulation_key = DecapsulationKey::<MlKem1024Params>::from_bytes(&encoded_dec_key);

        Ok(Self {
            encapsulation_key,
            decapsulation_key,
        })
    }

    #[wasm_bindgen(getter, js_name = "encapsulationKey")]
    pub fn encapsulation_key(&self) -> Vec<u8> {
        self.encapsulation_key.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = "decapsulationKey")]
    pub fn decapsulation_key(&self) -> Vec<u8> {
        self.decapsulation_key.as_bytes().to_vec()
    }

    #[wasm_bindgen]
    pub fn encapsulate(encapsulation_key: &[u8]) -> Result<MlKemEncapsulation, String> {
        let encoded_enc_key =
            Encoded::<EncapsulationKey<MlKem1024Params>>::try_from(encapsulation_key)
                .map_err(|e| format!("Could not get encoded encapsulation key from bytes: {e}"))?;

        let enc_key = EncapsulationKey::<MlKem1024Params>::from_bytes(&encoded_enc_key);

        let mut rng = rand::thread_rng();
        let (ciphertext, shared_secret) = enc_key
            .encapsulate(&mut rng)
            .map_err(|e| format!("Could not encapsulate: {e:?}"))?;

        Ok(MlKemEncapsulation {
            ciphertext: ciphertext.to_vec(),
            shared_secret: shared_secret.to_vec(),
        })
    }

    #[wasm_bindgen]
    pub fn decapsulate(decapsulation_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let encoded_dec_key =
            Encoded::<DecapsulationKey<MlKem1024Params>>::try_from(decapsulation_key)
                .map_err(|e| format!("Could not get encoded decapsulation key from bytes: {e}"))?;

        let dec_key = DecapsulationKey::<MlKem1024Params>::from_bytes(&encoded_dec_key);

        let ciphertext_array = Ciphertext::<Kem<MlKem1024Params>>::try_from(ciphertext)
            .map_err(|e| format!("Could not decode ciphertext: {e}"))?;

        let shared_secret = dec_key
            .decapsulate(&ciphertext_array)
            .map_err(|e| format!("Could not decapsulate: {e:?}"))?;

        Ok(shared_secret.to_vec())
    }
}
