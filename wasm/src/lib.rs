use simple_secrets::{Env, Sender as InnerSender, SimpleSecretsError};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "./randombytes.js")]
extern "C" {
    #[wasm_bindgen(js_name = "default")]
    fn rand_bytes(len: u32) -> Vec<u8>;
}

struct WasmEnv();

impl WasmEnv {
    fn fill_bytes(&self, data: &mut [u8]) {
        let rand = rand_bytes(data.len() as u32);
        data.copy_from_slice(&rand);
    }
}

impl Env for WasmEnv {
    fn new() -> Result<Self, SimpleSecretsError> {
        Ok(Self())
    }

    fn iv(&self) -> Result<[u8; 16], SimpleSecretsError> {
        let mut iv: [u8; 16] = [0; 16];
        self.fill_bytes(&mut iv);
        Ok(iv)
    }

    fn nonce(&self) -> Result<[u8; 16], SimpleSecretsError> {
        let mut nonce: [u8; 16] = [0; 16];
        self.fill_bytes(&mut nonce);
        Ok(nonce)
    }
}

#[wasm_bindgen]
pub struct Sender(InnerSender<WasmEnv>);

#[wasm_bindgen]
impl Sender {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &str) -> Result<Sender, JsValue> {
        Ok(Self(
            InnerSender::with_env(key, WasmEnv()).map_err(|e| e.to_string())?,
        ))
    }

    pub fn pack(&self, mut data: Vec<u8>) -> Result<String, JsValue> {
        self.0.pack_raw(&mut data).map_err(|e| e.to_string().into())
    }

    pub fn unpack(&self, data: String) -> Result<Vec<u8>, JsValue> {
        self.0.unpack_raw(data).map_err(|e| e.to_string().into())
    }
}
