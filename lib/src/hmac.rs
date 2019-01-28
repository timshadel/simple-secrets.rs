use crate::error::{CorruptPacketKind, SimpleSecretsError};
use aes::block_cipher_trait::generic_array::typenum::Unsigned;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn derive(master_key: &[u8], role: &str) -> HmacSha256 {
    let mut hash = Sha256::new();
    hash.input(master_key);
    hash.input(role);
    let key = hash.result();
    Hmac::new_varkey(&key).expect("invalid key length")
}

pub(crate) trait MacExt {
    fn append_mac(self, data: &mut Vec<u8>);
    fn verify_mac(self, data: &mut Vec<u8>) -> Result<(), SimpleSecretsError>;
}

impl<T: Mac> MacExt for T {
    fn append_mac(mut self, data: &mut Vec<u8>) {
        self.input(data);
        data.extend(self.result().code())
    }

    fn verify_mac(mut self, data: &mut Vec<u8>) -> Result<(), SimpleSecretsError> {
        let mac_offset = data.len() - T::OutputSize::to_usize();
        let body = &data[..mac_offset];
        self.input(body);
        if self.verify(&data[mac_offset..]).is_err() {
            return Err(CorruptPacketKind::NotAuthentic.into());
        }
        data.truncate(mac_offset);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn it_should_create_a_message_authentication_code() {
        let key = [0x9f; 32];
        let mut data = vec![0x11; 25];

        HmacSha256::new_varkey(&key)
            .expect("invalid key length")
            .append_mac(&mut data);

        assert_eq!(
            HEXLOWER.encode(&data[25..]),
            "adf1793fdef44c54a2c01513c0c7e4e71411600410edbde61558db12d0a01c65"
        );

        HmacSha256::new_varkey(&key)
            .expect("invalid key length")
            .verify_mac(&mut data)
            .unwrap();

        assert_eq!(data, [0x11; 25]);
    }
}
