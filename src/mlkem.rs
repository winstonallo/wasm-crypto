use ml_kem::{
    Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MlKemKeypair {
    encapsulation_key: Vec<u8>,
    decapsulation_key: Vec<u8>,
}

#[wasm_bindgen]
pub struct MlKemEncapsulation {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemKeypair {
    #[wasm_bindgen(getter, js_name = "encapsulationKey")]
    pub fn encapsulation_key(&self) -> Vec<u8> {
        self.encapsulation_key.to_owned()
    }

    #[wasm_bindgen(getter, js_name = "decapsulationKey")]
    pub fn decapsulation_key(&self) -> Vec<u8> {
        self.decapsulation_key.to_owned()
    }
}

#[wasm_bindgen]
impl MlKemEncapsulation {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.to_owned()
    }

    #[wasm_bindgen(getter, js_name = "sharedSecret")]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.to_owned()
    }
}

/// Generates an encapsulation (public), and a corresponding decapsulation (private)
/// [ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) key.
#[wasm_bindgen(js_name = "mlkemKeyGen")]
pub fn keygen() -> MlKemKeypair {
    let mut rng = rand::rngs::OsRng;
    let (decapsulation_key, encapsulation_key) = MlKem1024::generate(&mut rng);
    MlKemKeypair {
        encapsulation_key: encapsulation_key.as_bytes().to_vec(),
        decapsulation_key: decapsulation_key.as_bytes().to_vec(),
    }
}

/// The encapsulation algorithm [ML-KEM.Encaps](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf#algorithm.20)
/// accepts an encapsulation (public) key as input, generates randomness internally, and outputs an ML-KEM ciphertext and
/// shared secret.
///
/// The ciphertext can safely be sent to the owner of the corresponding decapsulation (private) key, who can then use it
/// to derive the same shared secret. The shared secret itself is a **secret** and shall be treated as such.
#[wasm_bindgen(js_name = "mlkemEncaps")]
pub fn encaps(
    #[wasm_bindgen(js_name = "encapsulationKey")] encapsulation_key: &[u8],
) -> Result<MlKemEncapsulation, String> {
    let encoded_encapsulation_key =
        Encoded::<EncapsulationKey<MlKem1024Params>>::try_from(encapsulation_key)
            .map_err(|e| format!("Could not get encoded encapsulation key from bytes: {e}"))?;
    let encapsulation_key =
        EncapsulationKey::<MlKem1024Params>::from_bytes(&encoded_encapsulation_key);
    let mut rng = rand::rngs::OsRng;
    let (ciphertext, shared_secret) = encapsulation_key
        .encapsulate(&mut rng)
        .map_err(|e| format!("Could not encapsulate: {e:?}"))?;

    Ok(MlKemEncapsulation {
        ciphertext: ciphertext.to_vec(),
        shared_secret: shared_secret.to_vec(),
    })
}

/// The decapsulation algorithm [ML-KEM.Decaps](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf#algorithm.21)
/// accepts a decapsulation (private) key and an ML-KEM ciphertext as input, does not use any randomness, and outputs a shared
/// secret.
#[wasm_bindgen(js_name = "mlkemDecaps")]
pub fn decaps(
    #[wasm_bindgen(js_name = "decapsulationKey")] decapsulation_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let encoded_decapsulation_key =
        Encoded::<DecapsulationKey<MlKem1024Params>>::try_from(decapsulation_key)
            .map_err(|e| format!("Could not get encoded decapsulation key from bytes: {e}"))?;
    let decapsulation_key =
        DecapsulationKey::<MlKem1024Params>::from_bytes(&encoded_decapsulation_key);
    let ciphertext_array = Ciphertext::<Kem<MlKem1024Params>>::try_from(ciphertext)
        .map_err(|e| format!("Could not decode ciphertext: {e}"))?;
    let shared_secret = decapsulation_key
        .decapsulate(&ciphertext_array)
        .map_err(|e| format!("Could not decapsulate: {e:?}"))?;

    Ok(shared_secret.to_vec())
}
