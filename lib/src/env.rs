use crate::error::SimpleSecretsError;
use rand_os::rand_core::RngCore;
use rand_os::OsRng;
use std::cell::RefCell;

pub trait Env: Sized {
    fn new() -> Result<Self, SimpleSecretsError>;
    fn iv(&self) -> Result<[u8; 16], SimpleSecretsError>;
    fn nonce(&self) -> Result<[u8; 16], SimpleSecretsError>;
}

pub struct SecureEnv(RefCell<OsRng>);

impl Env for SecureEnv {
    fn new() -> Result<Self, SimpleSecretsError> {
        let r = OsRng::new();
        match r {
            Ok(rng) => Ok(Self(RefCell::new(rng))),
            Err(e) => Err(SimpleSecretsError::RandomSourceUnavailable(e))
        }        
    }

    fn iv(&self) -> Result<[u8; 16], SimpleSecretsError> {
        self.nonce()
    }

    fn nonce(&self) -> Result<[u8; 16], SimpleSecretsError> {
        let mut value: [u8; 16] = [0; 16];
        self.0.borrow_mut().fill_bytes(&mut value);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn nonce_should_not_be_zeros() {
        let nonce = SecureEnv::new().unwrap().nonce().unwrap();
        let nonce = HEXLOWER.encode(&nonce);
        assert_ne!(nonce, "00000000000000000000000000000000");
    }
}
