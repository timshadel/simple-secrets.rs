use crate::{
    cipher::Cipher,
    error::{CorruptPacketKind, SimpleSecretsError},
    hmac::{derive as derive_hmac, MacExt},
};
use data_encoding::HEXLOWER_PERMISSIVE;
use hmac::Mac;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const KEY_LEN: usize = 6;

pub(crate) struct MasterKey {
    /// Master key used in all operations
    master_key: [u8; 32],

    // ID of the master key
    key_id: [u8; 6],
}

impl MasterKey {
    pub(crate) fn authenticate_packet(&self, data: &mut Vec<u8>) {
        let _ = data.splice(0..0, self.key_id.iter().cloned()).count();
        self.derive_sender_hmac().append_mac(data);
    }

    pub(crate) fn verify_packet(&self, data: &mut Vec<u8>) -> Result<(), SimpleSecretsError> {
        if data.len() <= 38 {
            return Err(CorruptPacketKind::TooShort.into());
        }

        self.verify_packet_id(&data[0..KEY_LEN])?;
        self.derive_sender_hmac().verify_mac(data)?;

        let _ = data.splice(..KEY_LEN, std::iter::empty()).count();

        Ok(())
    }

    fn verify_packet_id(&self, packet: &[u8]) -> Result<(), SimpleSecretsError> {
        let key_id = &self.key_id;

        if key_id.ct_eq(packet).unwrap_u8() == 1 {
            return Ok(());
        }

        let expected_id = HEXLOWER_PERMISSIVE.encode(key_id);
        let actual_id = HEXLOWER_PERMISSIVE.encode(packet);
        return Err(SimpleSecretsError::UnknownKey {
            expected_id,
            actual_id,
        });
    }

    pub(crate) fn sender_cipher(&self) -> Cipher {
        Cipher::derive(&self.master_key, "simple-crypto/sender-cipher-key")
    }

    #[allow(dead_code)]
    pub(crate) fn receiver_cipher(&self) -> Cipher {
        Cipher::derive(&self.master_key, "simple-crypto/receiver-cipher-key")
    }

    pub(crate) fn derive_sender_hmac(&self) -> impl Mac {
        derive_hmac(&self.master_key, "simple-crypto/sender-hmac-key")
    }

    #[allow(dead_code)]
    pub(crate) fn derive_receiver_hmac(&self) -> impl Mac {
        derive_hmac(&self.master_key, "simple-crypto/receiver-hmac-key")
    }
}

impl FromStr for MasterKey {
    type Err = SimpleSecretsError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let key_bytes = HEXLOWER_PERMISSIVE.decode(key.as_ref()).map_err(|e| {
            SimpleSecretsError::TextDecodingError {
                role: "master key",
                cause: e,
            }
        })?;

        if key_bytes.len() != 32 {
            return Err(SimpleSecretsError::InvalidKeyLength(key_bytes.len()));
        }

        let mut master_key: [u8; 32] = [0; 32];
        master_key.copy_from_slice(&key_bytes);

        let key_id = identify(&master_key);

        Ok(Self { master_key, key_id })
    }
}

impl From<[u8; 32]> for MasterKey {
    /// Construct a MasterKey with the given 256-bit master key.
    fn from(master_key: [u8; 32]) -> Self {
        let key_id = identify(&master_key);
        Self { master_key, key_id }
    }
}

impl Drop for MasterKey {
    /// Ensure that sensitive data is removed from memory
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.key_id.zeroize();
    }
}

fn identify(data: &[u8]) -> [u8; 6] {
    let mut len: [u8; 1] = [0; 1];
    len[0] = data.len() as u8;
    let mut hash = Sha256::new();
    hash.input(&len);
    hash.input(data);
    let mut result = hash.result();
    let mut final_result: [u8; 6] = [0; 6];
    final_result.copy_from_slice(&result[0..6]);
    result.zeroize();
    final_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn it_should_calculate_an_id_for_a_key() {
        let key = [0xab; 32];

        let id = identify(&key);
        let id = HEXLOWER.encode(&id);
        assert_eq!(id, "0d081b0889d7");
    }
}
