///
/// Expose primitives.
///
/// WARNING: Using any of these primitives in isolation could be Bad. Take cautious.
///


// Modules used

use crypto::{ buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::SymmetricCipherError;
use data_encoding::{ BASE64URL_NOPAD, DecodeError, DecodeKind, DecodePartial };
use rand::RngCore;
use rand::rngs::OsRng;
use rmp_serde::{ Deserializer, Serializer };
use serde::{ Deserialize, Serialize };


pub enum SimpleError {
    InvalidLength,
    InvalidMAC,
    InvalidPadding,
    InvalidSymbol,
    EncodingError,
    UnknownKey,
}

impl std::fmt::Debug for SimpleError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SimpleError::InvalidLength => write!(f, "Invalid length"),
            SimpleError::InvalidMAC => write!(f, "Invalid message authentication code"),
            SimpleError::InvalidPadding => write!(f, "Invalid padding"),
            SimpleError::InvalidSymbol => write!(f, "Invalid symbol"),
            SimpleError::EncodingError => write!(f, "Encoding error"),
            SimpleError::UnknownKey => write!(f, "Unknown key"),
        }
    }
}

//
// Public functions
//


/// Provide 16 securely random bytes.
pub fn nonce() -> [u8; 16] {
    let mut result: [u8; 16] = [0; 16];
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut result);
    return result;
}

/// Generate the authentication key for messages originating from
/// the channel's Sender side.
///
/// Uses the ASCII string 'simple-crypto/sender-hmac-key' as the role.
pub fn derive_sender_hmac(master_key: [u8; 32]) -> [u8; 32] {
    return derive(master_key, "simple-crypto/sender-hmac-key");
}

/// Generate the encryption key for messages originating from
/// the channel's Sender side.
///
/// Uses the ASCII string 'simple-crypto/sender-cipher-key' as the role.
pub fn derive_sender_key(master_key: [u8; 32]) -> [u8; 32] {
    return derive(master_key, "simple-crypto/sender-cipher-key");
}

/// Generate the authentication key for messages originating from
/// the channel's Receiver side.
///
/// Uses the ASCII string 'simple-crypto/receiver-hmac-key' as the role.
#[allow(dead_code)]
pub fn derive_receiver_hmac(master_key: [u8; 32]) -> [u8; 32] {
    return derive(master_key, "simple-crypto/receiver-hmac-key");
}

/// Generate the encryption key for messages originating from
/// the channel's Receiver side.
///
/// Uses the ASCII string 'simple-crypto/receiver-cipher-key' as the role.
#[allow(dead_code)]
pub fn derive_receiver_key(master_key: [u8; 32]) -> [u8; 32] {
    return derive(master_key, "simple-crypto/receiver-cipher-key");
}

/// Encrypt buffer with the given key.
///
/// Uses AES256 with a random 128-bit initialization vector.
pub fn encrypt(data: &[u8], key: [u8; 32], iv: Option<[u8; 16]>) -> Result<Vec<u8>, SimpleError> {
    let iv = iv.unwrap_or(nonce());
    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize256, &key,
        &iv, blockmodes::PkcsPadding);

    let mut ciphertext = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        ciphertext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok([&iv[..], &ciphertext[..]].concat())
}


/// Decrypt buffer with the given key.
pub fn decrypt(data: &[u8], key: [u8; 32], iv: [u8; 16]) -> Result<Vec<u8>, SimpleError> {
    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize256, &key,
        &iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

/// Create a short identifier for potentially sensitive data.
pub fn identify(data: &[u8]) -> [u8; 6] {
    let mut len: [u8; 1] = [0; 1];
    len[0] = data.len() as u8;
    let mut hash = Sha256::new();
    hash.input(&len);
    hash.input(data);
    let mut result: [u8; 32] = [0; 32];
    hash.result(&mut result);
    let mut final_result: [u8; 6] = [0; 6];
    final_result.copy_from_slice(&result[0..6]);
    final_result
}

/// Create a message authentication code for the given data.
///
/// Uses HMAC-SHA256.
pub fn mac(data: &[u8], key: [u8; 32]) -> [u8; 32] {
    let digest = Sha256::new();
    let mut hmac = Hmac::new(digest, &key);
    hmac.input(data);
    let mut result: [u8; 32] = [0; 32];
    hmac.raw_result(&mut result);
    result
}

/// Use a constant-time comparison algorithm to reduce
/// side-channel attacks.
///
/// Short-circuits only when the two buffers aren't the same length.
pub fn compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // constant-time compare
    //   hat-tip to https://github.com/freewil/scmp for |=
    let mut same = 0;
    for i in 0..a.len() {
        same |= a[i] ^ b[i];
    }
    return same == 0;
}

/// Turn a websafe string back into a binary buffer.
///
/// Uses base64url encoding.
pub fn binify(string: &[u8]) -> Result<Vec<u8>, SimpleError> {
    Ok(BASE64URL_NOPAD.decode(string)?)
}

/// Turn a binary buffer into a websafe string.
///
/// Uses base64url encoding.
pub fn stringify(data: &[u8]) -> String {
    BASE64URL_NOPAD.encode(data)
}

/// Turn a Rust type into a binary representation
/// suitable for use in crypto functions. This object will
/// possibly be deserialized in a different programming
/// environment—it should be representable in a JSON-like
/// in structure.
///
/// Uses serde for serialization into MsgPack format.
pub fn serialize<T: ?Sized>(value: &T) -> Result<Vec<u8>, SimpleError> where T: Serialize {
    let mut buf = Vec::<u8>::new();
    value.serialize(&mut Serializer::new(&mut buf)).unwrap();
    Ok(buf)
}


/// Turn a binary representation into a Rust structure
/// suitable for use in application logic. This object
/// possibly originated in a different programming
/// environment—it should be JSON-like in structure.
///
/// Uses serde for deserialization from MsgPack format.
pub fn deserialize<'a, 'b, T>(v: &'a [u8]) -> Result<T, SimpleError> where T: Deserialize<'b>, {
    let mut de = Deserializer::new(v);
    let value = Deserialize::deserialize(&mut de).unwrap();
    Ok(value)
}

/// Overwrite the contents of the buffer with zeroes.
/// This is critical for removing sensitive data from memory.
pub fn zero(buf: &mut [u8]) {
    for i in 0..buf.len() {
        buf[i] = 0;
    }
}


//
// Public Traits
//

pub trait ASCIIData {
    fn to_ascii_u8(&self) -> Vec<u8>;
}

impl ASCIIData for String {

    fn to_ascii_u8(&self) -> Vec<u8> {
        self.chars()
            .map(|c| c as u8)
            .collect::<Vec<_>>()
    }

}

impl ASCIIData for str {

    fn to_ascii_u8(&self) -> Vec<u8> {
        self.chars()
            .map(|c| c as u8)
            .collect::<Vec<_>>()
    }
    
}


//
// Private functions
//

/// Generate an encryption or hmac key from the master key and role.
fn derive(master_key: [u8; 32], role: &str) -> [u8; 32] {
    let role = role.to_ascii_u8();
    let mut hash = Sha256::new();
    hash.input(&master_key);
    hash.input(&role);
    let mut result: [u8; 32] = [0; 32];
    hash.result(&mut result);
    return result;
}

impl From<DecodeError> for SimpleError {

    fn from(err: DecodeError) -> Self {
        match err.kind {
            DecodeKind::Length => SimpleError::InvalidLength,
            DecodeKind::Symbol => SimpleError::InvalidSymbol,
            DecodeKind::Trailing => SimpleError::InvalidPadding,
            DecodeKind::Padding => SimpleError::InvalidPadding
        }
    }

}

impl From<DecodePartial> for SimpleError {

    fn from(partial: DecodePartial) -> Self {
        SimpleError::from(partial.error)
    }

}

impl From<SymmetricCipherError> for SimpleError {

    fn from(err: SymmetricCipherError) -> Self {
        match err {
            SymmetricCipherError::InvalidLength => SimpleError::InvalidLength,
            SymmetricCipherError::InvalidPadding => SimpleError::InvalidPadding
        }
    }

}


//
// Module Tests
//

#[cfg(test)]
mod tests {

    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn nonce_should_not_be_zeros() {
        let nonce = nonce();
        let nonce = HEXLOWER.encode(&nonce);
        assert_ne!(nonce, "00000000000000000000000000000000");
    }

    #[test]
    fn it_should_derive_sender_hmac_key() {
        let master_key = [0xbc; 32];

        let key = derive_sender_hmac(master_key);
        let key = HEXLOWER.encode(&key);
        assert_eq!(key, "1e2e2725f135463f05c268ffd1c1687dbc9dd7da65405697471052236b3b3088");
    }

    #[test]
    fn it_should_derive_sender_key() {
        let master_key = [0xbc; 32];

        let key = derive_sender_key(master_key);
        let key = HEXLOWER.encode(&key);
        assert_eq!(key, "327b5f32d7ff0beeb0a7224166186e5f1fc2ba681092214a25b1465d1f17d837");
    }

    #[test]
    fn it_should_derive_receiver_hmac_key() {
        let master_key = [0xbc; 32];

        let key = derive_receiver_hmac(master_key);
        let key = HEXLOWER.encode(&key);
        assert_eq!(key, "375f52dff2a263f2d0e0df11d252d25ba18b2f9abae1f0cbf299bab8d8c4904d");
    }

    #[test]
    fn it_should_derive_receiver_key() {
        let master_key = [0xbc; 32];

        let key = derive_receiver_key(master_key);
        let key = HEXLOWER.encode(&key);
        assert_eq!(key, "c7e2a9660369f243aed71b0de0c49ee69719d20261778fdf39991a456566ef22");
    }

    #[test]
    fn it_should_encrypt_data() {
        let key = [0xcd; 32];
        let plaintext = [0x11; 25];
        let output = encrypt(&plaintext, key, None).unwrap();

        // 16-byte IV, 32 bytes to encrypt the 25 data bytes
        assert_eq!(48, output.len());

        let mut iv: [u8; 16] = [0; 16];
        iv.copy_from_slice(&output[0..16]);
        let ciphertext = &output[16..];
        let recovered = decrypt(ciphertext, key, iv).ok().unwrap();

        let plaintext = HEXLOWER.encode(&plaintext);
        let recovered = HEXLOWER.encode(&recovered);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn it_should_decrypt_data() {
        let key = [0xcd; 32];
        let plaintext = [0x11; 25];
        let mut iv: [u8; 16] = [0; 16];
        let iv_bytes = HEXLOWER.decode(b"d4a5794c81015dde3b9b0648f2b9f5b9").unwrap();
        iv.copy_from_slice(&iv_bytes);
        let ciphertext = b"cb7f804ec83617144aa261f24af07023a91a3864601a666edea98938f2702dbc";
        let ciphertext = HEXLOWER.decode(ciphertext).unwrap();
        let recovered = decrypt(&ciphertext, key, iv).unwrap();

        let plaintext = HEXLOWER.encode(&plaintext);
        let recovered = HEXLOWER.encode(&recovered);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn it_should_calculate_an_id_for_a_key() {
        let key = [0xab; 32];

        let id = identify(&key);
        let id = HEXLOWER.encode(&id);
        assert_eq!(id, "0d081b0889d7");
    }

    #[test]
    fn it_should_create_a_message_authentication_code() {
        let key = [0x9f; 32];
        let data = [0x11; 25];

        let mac = mac(&data, key);
        let mac = HEXLOWER.encode(&mac);
        assert_eq!(mac, "adf1793fdef44c54a2c01513c0c7e4e71411600410edbde61558db12d0a01c65");
    }

    #[test]
    fn it_should_correctly_distinguish_data_equality() {
        let a = [0x11; 32];
        let b = [0x12; 25];
        let c = [0x11; 32];

        assert!(compare(&a, &a));
        assert!(!compare(&a, &b));
        assert!(compare(&a, &c));

        // TODO: add statistical test to show constant-time compare
    }

    #[test]
    fn it_should_binify_from_a_string() {
        let val = binify(b"cartinir90_-");
        let val = val.ok().unwrap();
        assert_eq!(val.len(), 9);
        let val = HEXLOWER.encode(&val);
        assert_eq!(val, "71aaed8a78abf74ffe")
    }

    #[test]
    fn it_should_stringify_data() {
        let data = [0x32; 10];
        let val = stringify(&data);
        assert_eq!(val, "MjIyMjIyMjIyMg");
    }

    #[test]
    fn it_should_serialize_and_deserialize_simple_types() {
        let num = 1;
        let text = "abcd";
        let arr = [0x32; 10];

        let binary = serialize(&num).unwrap();
        let actual: i32 = deserialize(&binary).unwrap();
        assert_eq!(1, actual);
        let binary = serialize(&text).unwrap();
        let actual: String = deserialize(&binary).unwrap();
        assert_eq!("abcd", actual);
        let binary = serialize(&arr).unwrap();
        let actual: [i32; 10] = deserialize(&binary).unwrap();
        assert_eq!([0x32; 10], actual);
    }

    #[test]
    fn it_zeros_buffers() {
        let mut b = [74, 68, 69, 73, 20, 69, 73, 20, 73, 0x6f, 0x6d, 65];
        let z = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let bStr = HEXLOWER.encode(&b);
        let zStr = HEXLOWER.encode(&z);
        assert_ne!(bStr, zStr);

        zero(&mut b[..]);
        let bStr = HEXLOWER.encode(&b);

        assert_eq!(bStr, zStr);
    }

}
