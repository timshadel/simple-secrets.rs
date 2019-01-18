
///
/// Module dependencies
///

mod primitives;

use crate::primitives::{ ASCIIData, SimpleError };
use data_encoding::HEXLOWER_PERMISSIVE;
use serde::{ Deserialize, Serialize };


///
/// Data types
///

pub struct Packet {
    master_key: [u8; 32]
}

pub fn packet(master: String) -> Result<Packet, SimpleError> {
    let mut key: [u8; 32] = [0; 32];
    let master = master.to_ascii_u8();
    let length = HEXLOWER_PERMISSIVE.decode_mut(&master, &mut key).map_err(primitives::map_decode_partial)?;
    if length != 32 {
        return Err(SimpleError::InvalidLength)
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
    pub fn pack<T: ?Sized>(&self, value: &T) -> Result<String, SimpleError> where T: Serialize {
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
    pub fn unpack<'a, T>(&self, websafe: String) -> Result<T, SimpleError> where T: Deserialize<'a> {
        let packet = primitives::binify(&websafe.to_ascii_u8())?;
        let mut cipherdata = self.verify(&packet[..])?;
        let body = self.decrypt_body(&mut cipherdata[..])?;
        primitives::deserialize(&body)
    }

}


///
/// Private functions
///

impl Packet {

    fn encrypt_body(&self, data: &mut [u8]) -> Result<Vec<u8>, SimpleError> {
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

    fn decrypt_body(&self, data: &mut [u8]) -> Result<Vec<u8>, SimpleError> {
        let mut iv: [u8; 16] = [0; 16];
        iv.copy_from_slice(&data[0..16]);
        let encrypted = &data[16..];
        let mut key = primitives::derive_sender_key(self.master_key);

        let mut nonce_with_body = primitives::decrypt(&encrypted, key, iv)?;
        let mut body = Vec::<u8>::new();
        body.extend(&nonce_with_body[16..]);
        primitives::zero(data);
        primitives::zero(&mut iv);
        primitives::zero(&mut key);
        primitives::zero(&mut nonce_with_body);

        Ok(body)
    }

    fn authenticate(&self, data: &mut [u8]) -> Vec<u8> {
        let id = primitives::identify(&self.master_key);
        let auth = [&id[..], &data[..]].concat();
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

    /// Verify the given data from the embedded message authentication code.
    ///
    /// Uses HMAC-SHA256.
    fn verify(&self, data: &[u8]) -> Result<Vec<u8>, SimpleError> {
        let key_id = primitives::identify(&self.master_key);
        if !primitives::compare(&key_id, &data[0..6]) {
            return Err(SimpleError::UnknownKey)
        }
        let mac_offset = data.len() - 32;
        if mac_offset <= 0 {
            return Err(SimpleError::InvalidLength)
        }
        let body = &data[0..mac_offset];
        let packet_mac = &data[mac_offset..];
        let hmac_key = primitives::derive_sender_hmac(self.master_key);
        let mac = primitives::mac(body, hmac_key);
        if !primitives::compare(packet_mac, &mac) {
            return Err(SimpleError::InvalidMAC)
        }
        let mut value = Vec::<u8>::new();
        // value.extend(&mac);
        value.extend(&body[6..]);
        Ok(value)
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
    use data_encoding::HEXLOWER;


    #[test]
    #[allow(unused_variables)]
    fn it_should_accept_64char_hex() -> Result<(), SimpleError> {
        let key = [0xbc; 32];
        let hex = HEXLOWER_PERMISSIVE.encode(&key);
        let packet = packet(hex)?;
        Ok(())
    }

    #[test]
    #[should_panic]
    fn it_should_only_accept_hex() {
        packet(String::from("not-a-hex-string")).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_should_only_accept_64char_hex() {
        packet(String::from("1dad")).unwrap();
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

    #[test]
    fn it_should_create_a_message_authentication_code() {
        let key = [0x9f; 32];
        let mut data = [0x11; 25];
        let sender = Packet { master_key: key };
        let packet = sender.authenticate(&mut data);
        let packet = HEXLOWER.encode(&packet);
        let expected = "63859a62011a".to_owned() + 
                "11111111111111111111111111111111111111111111111111" + 
                "ab284d107b0824901279f6bca8843be53175f20de633dd84c6610021b8b52824";
        assert_eq!(packet, expected);
    }

    #[test]
    fn it_should_verify_a_message_authentication_code() {
        let sender = Packet { master_key: [0x9f; 32] };
        let packet = "63859a62011a".to_owned() + 
                "11111111111111111111111111111111111111111111111111" + 
                "ab284d107b0824901279f6bca8843be53175f20de633dd84c6610021b8b52824";
        let packet = HEXLOWER.decode(&packet.to_ascii_u8()).unwrap();

        let data = sender.verify(&packet).unwrap();
        let data = HEXLOWER.encode(&data);
        assert_eq!(data, "11111111111111111111111111111111111111111111111111");
    }

    #[test]
    fn it_should_have_recoverable_ciphertext() -> Result<(), SimpleError> {
        let sender = Packet { master_key: [0xbc; 32] };
        let packet = sender.pack("this is a secret message")?;
        let result: String = sender.unpack(packet)?;
        assert_eq!(result, "this is a secret message");
        Ok(())
    }

    #[test]
    #[should_panic]
    fn it_should_not_be_recoverable_with_a_different_key() {
        let sender = Packet { master_key: [0xbc; 32] };
        let packet = sender.pack("this is a secret message").unwrap();

        let sender = Packet { master_key: [0xcb; 32] };
        let result: String = sender.unpack(packet).unwrap();
        assert_ne!(result, "this is a secret message");
    }

    #[test]
    fn it_should_recover_full_objects() -> Result<(), SimpleError> {
        let sender = Packet { master_key: [0xbc; 32] };
        let body = vec![String::from("this"), String::from("is a secret")];
        let packet = sender.pack(&body)?;
        let result: Vec<String> = sender.unpack(packet)?;
        assert_eq!(result, [String::from("this"), String::from("is a secret")]);
        Ok(())
    }

}


#[cfg(test)]
mod compatibility_tests {

    use super::*;
    use data_encoding::HEXLOWER;

    fn master_key() -> [u8; 32] {
        let mut key: [u8; 32] = [0; 32];
        let key_bytes = b"eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
        let key_bytes = HEXLOWER.decode(key_bytes).unwrap();
        key.copy_from_slice(&key_bytes);
        key
    }

    #[test]
    #[ignore]
    // TODO: when we can fake the IV and nonce
    fn it_should_create_strings_from_packets() -> Result<(), SimpleError> {
        let message = "This is the simple-secrets compatibility standard string.";
        let websafe_msgpack5 = String::from("W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNp54eHe8KRY2JqOo9H8bi3Hnm4G0-r5SNlXXhIW9S99qTxTwibKW7mLkaNMTeZ1ktDwx-4sjCpCnXPIyZe7-l6-o6XjIqazRdhGD6AH5ZS9UFqLpaqIowSUQ9CeiQeFBQ");

        let sender = Packet { master_key: master_key() };
        let packet = sender.pack(message)?;
        assert_eq!(packet, websafe_msgpack5);
        Ok(())
    }

    #[test]
    fn it_should_recover_strings_from_packets() -> Result<(), SimpleError> {
        let message = "This is the simple-secrets compatibility standard string.";
        let websafe_msgpack1 = String::from("W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0");
        let websafe_msgpack5 = String::from("W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNp54eHe8KRY2JqOo9H8bi3Hnm4G0-r5SNlXXhIW9S99qTxTwibKW7mLkaNMTeZ1ktDwx-4sjCpCnXPIyZe7-l6-o6XjIqazRdhGD6AH5ZS9UFqLpaqIowSUQ9CeiQeFBQ");

        let sender = Packet { master_key: master_key() };
        // TODO: when we can fake the IV and nonce
        // let packet = sender.pack(message)?;
        // assert_eq!(packet, websafe_msgpack5);

        let output: String = sender.unpack(websafe_msgpack1)?;
        assert_eq!(output, message);
        let output: String = sender.unpack(websafe_msgpack5)?;
        assert_eq!(output, message);
        Ok(())
    }

}