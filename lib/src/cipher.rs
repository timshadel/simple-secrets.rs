use crate::error::SimpleSecretsError;
use aes::{
    block_cipher_trait::{
        generic_array::{typenum::Unsigned, GenericArray},
        BlockCipher,
    },
    Aes256,
};
use block_modes::{
    block_padding::{Padding, Pkcs7},
    BlockMode, Cbc,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type KeySize = <Aes256 as BlockCipher>::KeySize;
type BlockSize = <Aes256 as BlockCipher>::BlockSize;
type IVSize = <Aes256 as BlockCipher>::BlockSize;

pub(crate) struct Cipher(GenericArray<u8, KeySize>);

impl Cipher {
    pub(crate) fn derive(master_key: &[u8], role: &str) -> Self {
        let mut hash = Sha256::new();
        hash.input(master_key);
        hash.input(role);
        let key = hash.result();
        Cipher(key)
    }

    /// Encrypt buffer with the given key.
    ///
    /// Uses AES256 with a random 128-bit initialization vector.
    pub(crate) fn encrypt(
        &self,
        iv: &GenericArray<u8, BlockSize>,
        nonce: &GenericArray<u8, BlockSize>,
        data: &[u8],
    ) -> Result<Vec<u8>, SimpleSecretsError> {
        let cipher = Aes256Cbc::new_fix(&self.0, iv);
        let block_size = BlockSize::to_usize();
        let iv_size = IVSize::to_usize();
        let pos = nonce.len() + data.len();
        let buffer_size = pos + block_size + iv_size;
        let mut buffer = Vec::with_capacity(buffer_size);
        buffer.extend_from_slice(iv);
        buffer.extend_from_slice(nonce);
        buffer.extend_from_slice(data);
        buffer.resize(buffer_size, 0);

        let n = cipher.encrypt(&mut buffer[iv_size..], pos)?.len();
        buffer.truncate(n + iv_size);
        Ok(buffer)
    }

    /// Decrypt buffer with the given key.
    pub(crate) fn decrypt(&self, buffer: &mut Vec<u8>) -> Result<(), SimpleSecretsError> {
        let block_size = BlockSize::to_usize();
        let iv_size = IVSize::to_usize();
        Aes256Cbc::new_var(&self.0, &buffer[..iv_size])
            .expect("invalid IV length")
            .decrypt(&mut buffer[iv_size..])?;

        let n = Pkcs7::unpad(buffer)?.len();
        buffer.truncate(n);

        // Trim iv + nonce
        let trim = block_size + iv_size;
        buffer[..trim].zeroize();
        let _ = buffer.splice(..trim, std::iter::empty()).count();

        Ok(())
    }
}

impl Drop for Cipher {
    /// Ensure that sensitive data is removed from memory
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{Env, SecureEnv};
    use data_encoding::HEXLOWER;

    #[test]
    fn it_should_decrypt_data() {
        let key = [0xcd; 32];
        let nonce_plaintext = [0x11; 25];
        let mut recovered = vec![];
        recovered.extend(
            HEXLOWER
                .decode(b"d4a5794c81015dde3b9b0648f2b9f5b9")
                .unwrap(),
        );
        recovered.extend(
            HEXLOWER
                .decode(b"cb7f804ec83617144aa261f24af07023a91a3864601a666edea98938f2702dbc")
                .unwrap(),
        );
        Cipher(key.into()).decrypt(&mut recovered).unwrap();

        let plaintext = HEXLOWER.encode(&nonce_plaintext[BlockSize::to_usize()..]);
        let recovered = HEXLOWER.encode(&recovered);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn it_should_encrypt_data() {
        let key = [0xcd; 32];
        let plaintext = [0x11; 25];
        let iv = SecureEnv::new().unwrap().iv().unwrap();
        let output = Cipher(key.into())
            .encrypt(&iv.into(), &iv.into(), &plaintext)
            .unwrap();

        // 16-byte IV, 16-byte nonce, 64 bytes to encrypt the 25 data bytes
        assert_eq!(64, output.len());

        let mut recovered = output.to_vec();
        Cipher(key.into()).decrypt(&mut recovered).unwrap();

        let plaintext = HEXLOWER.encode(&plaintext);
        let recovered = HEXLOWER.encode(&recovered);
        assert_eq!(recovered, plaintext);
    }
}
