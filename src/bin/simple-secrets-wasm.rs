use data_encoding::HEXLOWER;
use simple_secrets::{Env, Packet, SimpleSecretsError};

// TODO use wasm-bindgen to get env working

struct WasmTestEnv();

impl Env for WasmTestEnv {
    fn new() -> Result<Self, SimpleSecretsError> {
        Ok(Self())
    }

    fn iv(&self) -> Result<[u8; 16], SimpleSecretsError> {
        let mut iv: [u8; 16] = [0; 16];
        let iv_bytes = b"7f3333233ce9235860ef902e6d0fcf35";
        let iv_bytes = HEXLOWER.decode(iv_bytes).unwrap();
        iv.copy_from_slice(&iv_bytes);
        Ok(iv)
    }

    fn nonce(&self) -> Result<[u8; 16], SimpleSecretsError> {
        let mut nonce: [u8; 16] = [0; 16];
        let nonce_bytes = b"83dcf5916c0b5c4bc759e44f9f5c8c50";
        let nonce_bytes = HEXLOWER.decode(nonce_bytes).unwrap();
        nonce.copy_from_slice(&nonce_bytes);
        Ok(nonce)
    }
}

fn sender() -> Result<Packet<WasmTestEnv>, SimpleSecretsError> {
    let key = "eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
    Packet::with_env(key, WasmTestEnv())
}

#[no_mangle]
pub extern "C" fn encode_number(number: u32) -> *const u8 {
    let packet = sender().unwrap();
    let res = packet.pack(&number).unwrap();
    res.as_ptr()
}

pub fn main() {}
