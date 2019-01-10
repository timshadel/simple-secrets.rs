
///
/// Module dependencies.
///

mod primitives;

use data_encoding::HEXLOWER_PERMISSIVE;
use serde::{ Deserialize, Serialize };


///
/// Data types
///

pub struct Packet {
    master_key: [u8; 32]
}

pub fn packet(master: String) -> Result<Packet, primitives::SimpleError> {
    let mut key: [u8; 32] = [0; 32];
    let master = master.to_ascii_lowercase()
                    .chars()
                    .map(|c| c as u8)
                    .collect::<Vec<_>>();
    let length = HEXLOWER_PERMISSIVE.decode_mut(&master, &mut key).map_err(primitives::map_decode_partial)?;
    if length != 32 {
        return Err(primitives::SimpleError::InvalidLength)
    }
    Ok(Packet { master_key: key })
}


///
/// Public functions
///

impl Packet {

    /// Turn a Rust type into an encrypted packet. This object will
    /// possibly be deserialized in a different programming
    /// environment—it should be JSON-like in structure.
    pub fn pack<T: ?Sized>(&self, value: &T) -> Result<String, primitives::SimpleError> where T: Serialize {
        let mut data = primitives::serialize(value)?;
        let mut body = self.encrypt_body(&mut data)?;
        let mut packet = self.authenticate(&mut body);
        let websafe = primitives::stringify(&packet);
        primitives::zero(&mut packet);

        Ok(websafe)
    }

    /// Turn an encrypted packet into a Rust structure. This
    /// object possibly originated in a different programming
    /// environment—it should be JSON-like in structure.
    pub fn deserialize<'a, T>(&self, packet: String) -> Result<T, primitives::SimpleError> where T: Deserialize<'a> {
        Err(primitives::SimpleError::EncodingError)
    }

}


///
/// Private functions
///

impl Packet {

    fn encrypt_body(&self, data: &mut [u8]) -> Result<Vec<u8>, primitives::SimpleError> {
        let mut nonce = primitives::nonce();
        let mut body = [&nonce[..], &data[..]].concat();
        let mut key = primitives::derive_sender_key(self.master_key);

        let cipherdata = primitives::encrypt(&body, key)?;
        primitives::zero(data);
        primitives::zero(&mut nonce);
        primitives::zero(&mut body);
        primitives::zero(&mut key);
        
        Ok(cipherdata)
    }

    fn authenticate(&self, data: &mut [u8]) -> Vec<u8> {
        let id = primitives::identify(&self.master_key);
        let mut auth = [&id[..], &data[..]].concat();
        let mut hmac_key = primitives::derive_sender_hmac(self.master_key);

        let mut mac = primitives::mac(&auth, hmac_key);
        let mut packet = Vec::<u8>::new();
        packet.extend(auth);
        packet.extend(mac.iter());

        primitives::zero(data);
        primitives::zero(&mut hmac_key);
        primitives::zero(&mut mac);

        packet
    }

}

impl Drop for Packet {

    /// Ensure that sensitive data is removed from memory
    fn drop(&mut self) {
        primitives::zero(&mut self.master_key);
    }

}


//
// Module Tests
//

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_should_accept_64char_hex() -> Result<(), primitives::SimpleError> {
        let key = [0xbc; 32];
        let hex = HEXLOWER_PERMISSIVE.encode(&key);
        let packet = packet(hex)?;
        Ok(())
    }

    #[test]
    #[should_panic]
    fn it_should_only_accept_64char_hex() {
        packet(String::from("not-a-hex-string")).unwrap();
    }

    #[test]
    fn it_should_make_websafe_strings() {
        let key = [0xbc; 32];
        let sender = Packet { master_key: key };
        let p = sender.pack("this is a secret message").unwrap();
        for (i, c) in p.chars().enumerate() {
            let is_base64_url = ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z');
            let is_base64_url = is_base64_url || ('0' <= c && c <= '9') || c == '-' || c == '_';
            assert!(is_base64_url, "Character is not base64url: {} at {} in {}", c, i, p);
        }
    }

}
