
///
/// Module dependencies
///

#[macro_use] extern crate failure;

mod primitives;

pub use crate::primitives::SimpleSecretsError;

use crate::primitives::ASCIIData;
use crate::primitives::SimpleSecretsError::*;
use crate::primitives::CorruptPacketKind::*;
use data_encoding::HEXLOWER_PERMISSIVE;
use serde::{ Deserialize, Serialize };


//
// Data types
//

/// Converts serializable data to and from websafe strings.
pub struct Packet {

    /// Master key used in all operations
    master_key: [u8; 32],

    /// Function to generate an IV during encryption. Defaults to random
    /// bytes, but overridden during compatibility tests for predictability.
    iv: fn() -> Result<[u8; 16], SimpleSecretsError>,

    /// Function to generate a nonce during encryption. Defaults to random
    /// bytes, but overridden during compatibility tests for predictability.
    nonce: fn() -> Result<[u8; 16], SimpleSecretsError>
}


//
// Public functions
//

impl Packet {

    /// Construct a Packet with the given master key. Must be 64 hex characters.
    pub fn new(master: String) -> Result<Packet, SimpleSecretsError> {
        let master = master.to_ascii_u8();
        let key_bytes = HEXLOWER_PERMISSIVE.decode(&master).map_err(|e| TextDecodingError("master key", e))?;
        if key_bytes.len() != 32 {
            return Err(InvalidKeyLength(key_bytes.len()))
        }
        let mut key: [u8; 32] = [0; 32];
        key.copy_from_slice(&key_bytes);
        Ok(Packet::from(key))
    }

    /// Turn a Rust type into an encrypted packet. This object will
    /// possibly be deserialized in a different programming
    /// environment—it should be JSON-like in structure.
    pub fn pack<T: ?Sized>(&self, value: &T) -> Result<String, SimpleSecretsError> where T: Serialize {
        let mut data = primitives::serialize(value)?;
        self.pack_raw(&mut data)
    }

    /// Turn an encrypted packet into a Rust structure. This
    /// object possibly originated in a different programming
    /// environment—it should be JSON-like in structure.
    pub fn unpack<'a, T>(&self, websafe: String) -> Result<T, SimpleSecretsError> where T: Deserialize<'a> {
        let body = self.unpack_raw(websafe)?;
        primitives::deserialize(&body)
    }

    /// Encrypt a packet into raw bytes. This allows the caller
    /// to issue app-specific typesafe serialization calls beforehand.
    pub fn pack_raw(&self, data: &mut Vec<u8>) -> Result<String, SimpleSecretsError> {
        let mut body = self.encrypt_body(data)?;
        let mut packet = self.authenticate(&mut body);
        let websafe = primitives::stringify(&packet);
        primitives::zero(&mut packet);

        Ok(websafe)
    }

    /// Decrypt a packet into raw bytes. This allows the caller
    /// to issue app-specific typesafe deserialization calls later.
    pub fn unpack_raw(&self, websafe: String) -> Result<Vec<u8>, SimpleSecretsError> {
        let packet = primitives::binify(&websafe.to_ascii_u8())?;
        let mut cipherdata = self.verify(&packet[..])?;
        self.decrypt_body(&mut cipherdata[..])
    }

}


//
// Private functions
//

impl Packet {

    fn encrypt_body(&self, data: &mut [u8]) -> Result<Vec<u8>, SimpleSecretsError> {
        let mut nonce = (self.nonce)()?;
        let mut body = [&nonce[..], &data[..]].concat();
        let mut key = primitives::derive_sender_key(self.master_key);

        let cipherdata = primitives::encrypt(&body, key, Some((self.iv)()?))?;
        primitives::zero(data);
        primitives::zero(&mut nonce);
        primitives::zero(&mut body);
        primitives::zero(&mut key);
        
        Ok(cipherdata)
    }

    fn decrypt_body(&self, data: &mut [u8]) -> Result<Vec<u8>, SimpleSecretsError> {
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
    fn verify(&self, data: &[u8]) -> Result<Vec<u8>, SimpleSecretsError> {
        if data.len() <= 38 {
            return Err(CorruptPacket(TooShort))
        }
        let key_id = primitives::identify(&self.master_key);
        if !primitives::compare(&key_id, &data[0..6]) {
            let expected = HEXLOWER_PERMISSIVE.encode(&key_id);
            let found = HEXLOWER_PERMISSIVE.encode(&data[0..6]);
            return Err(UnknownKey(found, expected))
        }
        let mac_offset = data.len() - 32;
        let body = &data[0..mac_offset];
        let packet_mac = &data[mac_offset..];
        let hmac_key = primitives::derive_sender_hmac(self.master_key);
        let mac = primitives::mac(body, hmac_key);
        if !primitives::compare(packet_mac, &mac) {
            return Err(CorruptPacket(NotAuthentic))
        }
        let mut value = Vec::<u8>::new();
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

impl From<[u8; 32]> for Packet {

    /// Construct a Packet with the given 256-bit master key.
    fn from(key: [u8; 32]) -> Self {
        Packet {
            master_key: key,
            iv: primitives::nonce,
            nonce: primitives::nonce
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
    #[allow(unused_variables)]
    fn it_should_accept_64char_hex() -> Result<(), SimpleSecretsError> {
        let key = [0xbc; 32];
        let hex = HEXLOWER_PERMISSIVE.encode(&key);
        let packet = Packet::new(hex)?;
        Ok(())
    }

    #[test]
    #[should_panic]
    fn it_should_only_accept_hex() {
        Packet::new(String::from("not-a-hex-string")).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_should_only_accept_64char_hex() {
        Packet::new(String::from("1dad")).unwrap();
    }

    #[test]
    fn it_should_make_websafe_strings() {
        let sender = Packet::from([0xbc; 32]);
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
        let sender = Packet::from(key);
        let packet = sender.authenticate(&mut data);
        let packet = HEXLOWER.encode(&packet);
        let expected = "63859a62011a".to_owned() + 
                "11111111111111111111111111111111111111111111111111" + 
                "ab284d107b0824901279f6bca8843be53175f20de633dd84c6610021b8b52824";
        assert_eq!(packet, expected);
    }

    #[test]
    fn it_should_verify_a_message_authentication_code() {
        let sender = Packet::from([0x9f; 32]);
        let packet = "63859a62011a".to_owned() + 
                "11111111111111111111111111111111111111111111111111" + 
                "ab284d107b0824901279f6bca8843be53175f20de633dd84c6610021b8b52824";
        let packet = HEXLOWER.decode(&packet.to_ascii_u8()).unwrap();

        let data = sender.verify(&packet).unwrap();
        let data = HEXLOWER.encode(&data);
        assert_eq!(data, "11111111111111111111111111111111111111111111111111");
    }

    #[test]
    fn it_should_have_recoverable_ciphertext() -> Result<(), SimpleSecretsError> {
        let sender = Packet::from([0xbc; 32]);
        let packet = sender.pack("this is a secret message")?;
        let result: String = sender.unpack(packet)?;
        assert_eq!(result, "this is a secret message");
        Ok(())
    }

    #[test]
    #[should_panic]
    fn it_should_not_be_recoverable_with_a_different_key() {
        let sender = Packet::from([0xbc; 32]);
        let packet = sender.pack("this is a secret message").unwrap();

        let sender = Packet::from([0xcb; 32]);
        let result: String = sender.unpack(packet).unwrap();
        assert_ne!(result, "this is a secret message");
    }

    #[test]
    fn it_should_recover_full_objects() -> Result<(), SimpleSecretsError> {
        let sender = Packet::from([0xbc; 32]);
        let body = vec![String::from("this"), String::from("is a secret")];
        let packet = sender.pack(&body)?;
        let result: Vec<String> = sender.unpack(packet)?;
        assert_eq!(result, [String::from("this"), String::from("is a secret")]);
        Ok(())
    }

}



//
// Cross-language compatibility tests
//

#[cfg(test)]
mod compatibility {

    use super::*;
    use data_encoding::HEXLOWER;

    fn compat_sender() -> Packet {        
        let mut key: [u8; 32] = [0; 32];
        let key_bytes = b"eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
        let key_bytes = HEXLOWER.decode(key_bytes).unwrap();
        key.copy_from_slice(&key_bytes);

        fn compat_iv() -> Result<[u8; 16], SimpleSecretsError> {
            let mut iv: [u8; 16] = [0; 16];
            let iv_bytes = b"7f3333233ce9235860ef902e6d0fcf35";
            let iv_bytes = HEXLOWER.decode(iv_bytes).unwrap();
            iv.copy_from_slice(&iv_bytes);
            Ok(iv)
        }

        fn compat_nonce() -> Result<[u8; 16], SimpleSecretsError> {
            let mut nonce: [u8; 16] = [0; 16];
            let nonce_bytes = b"83dcf5916c0b5c4bc759e44f9f5c8c50";
            let nonce_bytes = HEXLOWER.decode(nonce_bytes).unwrap();
            nonce.copy_from_slice(&nonce_bytes);
            Ok(nonce)
        }

        Packet {
            master_key: key,
            iv: compat_iv,
            nonce: compat_nonce
        }
    }

    mod string {

        use super::*;

        static COMPAT_STRING: &str = "This is the simple-secrets compatibility standard string.";
        static WEBSAFE_MSGPACK_1: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0";
        static WEBSAFE_MSGPACK_5: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNp54eHe8KRY2JqOo9H8bi3Hnm4G0-r5SNlXXhIW9S99qTxTwibKW7mLkaNMTeZ1ktDwx-4sjCpCnXPIyZe7-l6-o6XjIqazRdhGD6AH5ZS9UFqLpaqIowSUQ9CeiQeFBQ";

        #[test]
        fn it_creates_packets_from_strings() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let packet = sender.pack(COMPAT_STRING)?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_strings() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let output: String = sender.unpack(String::from(WEBSAFE_MSGPACK_1))?;
            assert_eq!(output, COMPAT_STRING);
            let output: String = sender.unpack(String::from(WEBSAFE_MSGPACK_5))?;
            assert_eq!(output, COMPAT_STRING);
            Ok(())
        }

    }

    mod binary {

        use super::*;
        use serde_bytes::ByteBuf;

        static WEBSAFE_MSGPACK_1: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yOnGuj4lHrhU_Uv8rMbpjXQJiqd3OMdktrw1asMDXy6jyLrVe9Ea-W09XC90Dgaxlk";
        static WEBSAFE_MSGPACK_5: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMVgYX8jn_wUmumA0aJMLlWffSYU0oaJsyJsVjxxF96Ia6mZgAalv5iywbsKORqxtQ";

        fn compat_bytes() -> ByteBuf {
            ByteBuf::from(&[0x32; 10][..])
        }

        #[test]
        fn it_creates_packets_from_bytes() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let packet = sender.pack(&compat_bytes())?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_bytes() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let output: ByteBuf = sender.unpack(String::from(WEBSAFE_MSGPACK_1))?;
            assert_eq!(output, compat_bytes());
            let output: ByteBuf = sender.unpack(String::from(WEBSAFE_MSGPACK_5))?;
            assert_eq!(output, compat_bytes());
            Ok(())
        }

    }

    mod numbers {

        use super::*;

        static COMPAT_NUMBER: u16 = 65234;
        static WEBSAFE_MSGPACK_1: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yN5I1SH6a75Y_qQlQIclwrVyOk6jJJnMrjeOm6D27_wD0DxwIY9cxSw8boQDgEsLKg";
        // Note: No change to numbers encoding in MsgPack5

        #[test]
        fn it_creates_packets_from_numbers() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let packet = sender.pack(&COMPAT_NUMBER)?;
            assert_eq!(packet, WEBSAFE_MSGPACK_1);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_numbers() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let output: u16 = sender.unpack(String::from(WEBSAFE_MSGPACK_1))?;
            assert_eq!(output, COMPAT_NUMBER);
            Ok(())
        }

    }

    mod nil {

        use super::*;

        static WEBSAFE_MSGPACK_1: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yPYBCYpYMU-4WChi6L1O1GCEApGRhWlg13kVPLTb90cXcEN9vpYgvttgcBJBh6Tjv8";
        // Note: No change to nil encoding in MsgPack5

        #[test]
        fn it_creates_packets_from_nil() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let unit = ();
            let packet = sender.pack(&unit)?;
            assert_eq!(packet, WEBSAFE_MSGPACK_1);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_nil() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let output: () = sender.unpack(String::from(WEBSAFE_MSGPACK_1))?;
            assert_eq!(output, ());
            Ok(())
        }

    }

    mod arrays {

        use super::*;

        static WEBSAFE_MSGPACK_1: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMKAFsDUUYwc2fKvPhP_RHYhDOUfJ58li1gJgg9sVeaKx9yC0vFkpxuTmzJP6hZjn6XXlrG6A7-EeNgyzvP547booi2LUi0ALyAzbCaR8abXqnzoNwITRz7TL0J_NkP2gfxbpwUvyBo8ZT0cxGRr9jGnW5F5s6D0jmKZTl209nDJEpXDFRDXCo5y08tmvMNogs7rsZYz74mAap3mrBS-J7W";
        static WEBSAFE_MSGPACK_5: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yP5Au9NtEbC-uoWkSPKgnAjODduuH_a2tH-zXaPNdqScWNR8snsQK2OufCVnb2OFk8O7VwgrObvx5gnGgC3pOsmk2Z5CasmOAfzn0B6uEnaBpiMOs74d0d70t07J4MdCRs1aDai9SJqxMpbjz5KJpVmSWqnT3n5KhzEdTLQwCuXQhSA0JKFaAlwQHh5tzq6ToWZZVR34REAGdAo7RMLSSi3";

        fn compat_array() -> Vec<String> {
            let mut arr = Vec::<String>::new();
            arr.push(String::from("This is the simple-secrets compatibility standard array."));
            arr.push(String::from("This is the simple-secrets compatibility standard array."));
            arr
        }

        #[test]
        fn it_creates_packets_from_an_array() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let packet = sender.pack(&compat_array())?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_an_array() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let output: Vec<String> = sender.unpack(String::from(WEBSAFE_MSGPACK_1))?;
            assert_eq!(output, compat_array());
            let output: Vec<String> = sender.unpack(String::from(WEBSAFE_MSGPACK_5))?;
            assert_eq!(output, compat_array());
            Ok(())
        }

    }

    mod maps {

        use super::*;
        use std::collections::HashMap;

        static WEBSAFE_MSGPACK_1: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXYKrvvhyLbyFTsndgOx5M5yockEUwdSgv6jG_JYpAiU5R37Y7OIZnF3IN2EWtaFSuJko0ajcvoYgDPeLMvjAJdRyBUYIKcvR-g56_p4O7Uef3yJRnfCprG6jUdMyDBai_";
        static WEBSAFE_MSGPACK_5: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXsI6Zwegq5A48uq2i-l13bNQWLY9Ho-lG_s6PzwQhjGz6BnCwAK66YsDBlTqflM-X1mviccZbvUV7K6i2ZPOs8gDUtMIVnu-ByDFopGwZUHjelkUZiLZcRKWXIYSLWyKp";

        fn compat_map() -> HashMap<String, String> {
            let mut arr = HashMap::new();
            arr.insert(String::from("compatibility-key"),
                String::from("This is the simple-secrets compatibility standard map."));
            arr
        }

        #[test]
        fn it_creates_packets_from_a_map() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let packet = sender.pack(&compat_map())?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_a_map() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender();
            let output: HashMap<String, String> = sender.unpack(String::from(WEBSAFE_MSGPACK_1))?;
            assert_eq!(output, compat_map());
            let output: HashMap<String, String> = sender.unpack(String::from(WEBSAFE_MSGPACK_5))?;
            assert_eq!(output, compat_map());
            Ok(())
        }

    }

}