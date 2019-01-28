mod cipher;
mod encoding;
mod env;
mod error;
mod hmac;
mod key;

pub use self::{
    env::{Env, SecureEnv},
    error::{CorruptPacketKind, SimpleSecretsError},
};

use crate::key::MasterKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

//
// Data types
//

/// Converts serializable data to and from websafe strings.
pub struct Packet<E: Env = SecureEnv> {
    /// Master key used in all operations
    master_key: MasterKey,

    // Environment for random data
    env: E,
}

//
// Public functions
//

impl Packet<SecureEnv> {
    /// Construct a Packet with the given master key. Must be 64 hex characters.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a problem with the key. The error kind can be:
    ///
    /// - [`TextDecodingError`] if key string is anything but an even number of
    ///   hex characters.
    /// - [`InvalidKeyLength`] if the key is not exactly 64 hex characters (32 bytes).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use simple_secrets::Packet;
    /// // Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
    /// // 64-char hex string master key (32 bytes, 256 bits)
    /// let key = "eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
    /// let sender = Packet::new(key).unwrap();
    /// ```
    ///
    /// [`TextDecodingError`]: enum.SimpleSecretsError.html#variant.TextDecodingError
    /// [`InvalidKeyLength`]: enum.SimpleSecretsError.html#variant.InvalidKeyLength
    pub fn new<K: AsRef<str>>(master: K) -> Result<Self, SimpleSecretsError> {
        Self::with_env(master, Env::new()?)
    }
}

impl<E: Env> Packet<E> {
    /// Construct a Packet with the given master key and Env.
    pub fn with_env<K: AsRef<str>>(master: K, env: E) -> Result<Self, SimpleSecretsError> {
        let master_key = master.as_ref().parse()?;
        Ok(Self { master_key, env })
    }
}

impl<E: Env> Packet<E> {
    /// Turn a Rust type into an encrypted packet. This object will
    /// possibly be deserialized in a different programming
    /// environment—it should be JSON-like in structure.
    ///
    /// # Errors
    ///
    /// Returns a [`SimpleSecretsError`] if there is a problem at any point
    /// in the process of serializing, encrypting, authenticating, and serializing
    /// the data. The various scenarios are described in the doc for that error type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use simple_secrets::Packet;
    /// // Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
    /// // 64-char hex string master key (32 bytes, 256 bits)
    /// let key = "eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
    /// let sender = Packet::new(key).unwrap();
    /// let packet = sender.pack("this is a secret message").unwrap();
    /// ```
    ///
    /// [`SimpleSecretsError`]: enum.SimpleSecretsError.html
    pub fn pack<T: ?Sized>(&self, value: &T) -> Result<String, SimpleSecretsError>
    where
        T: Serialize,
    {
        let mut data = encoding::serialize(value)?;
        self.pack_raw(&mut data)
    }

    /// Turn an encrypted packet into a Rust structure. This
    /// object possibly originated in a different programming
    /// environment—it should be JSON-like in structure.
    ///
    /// # Errors
    ///
    /// Returns a [`SimpleSecretsError`] if there is a problem at any point
    /// in the process of decoding, verifying, decrypting, and deserializing
    /// the data. The various scenarios are described in the doc for that
    /// error type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use simple_secrets::Packet;
    /// use std::collections::HashMap;
    /// // Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
    /// // 64-char hex string master key (32 bytes, 256 bits)
    /// let key = "eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
    /// let sender = Packet::new(key).unwrap();
    /// // Read data from somewhere
    /// let packet = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yPxFiG2Im\
    ///               V3GB2Hc31VDlX9KaxdK0mUdyBu5BnhraJ7s9ilG1cRUxGFCcPksnt_JDw";
    /// // let secret_message: String = sender.unpack(packet).unwrap();
    /// // assert_eq!(secret_message, "secret message");
    /// ```
    ///
    /// [`SimpleSecretsError`]: enum.SimpleSecretsError.html
    pub fn unpack<'a, T, S: AsRef<str>>(&self, websafe: S) -> Result<T, SimpleSecretsError>
    where
        T: Deserialize<'a>,
    {
        let mut body = self.unpack_raw(websafe)?;
        let result = encoding::deserialize(&body);
        body.zeroize();
        result
    }

    /// Encrypt a packet into raw bytes. This allows the caller
    /// to issue app-specific typesafe serialization calls beforehand.
    pub fn pack_raw(&self, data: &mut [u8]) -> Result<String, SimpleSecretsError> {
        let mut packet = self.encrypt_body(data)?;
        self.master_key.authenticate_packet(&mut packet);
        let websafe = encoding::stringify(&packet);
        packet.zeroize();
        Ok(websafe)
    }

    /// Decrypt a packet into raw bytes. This allows the caller
    /// to issue app-specific typesafe deserialization calls later.
    pub fn unpack_raw<S: AsRef<str>>(&self, websafe: S) -> Result<Vec<u8>, SimpleSecretsError> {
        let mut packet = encoding::binify(websafe)?;
        self.master_key.verify_packet(&mut packet)?;
        self.master_key.sender_cipher().decrypt(&mut packet)?;
        Ok(packet)
    }
}

//
// Private functions
//

impl<E: Env> Packet<E> {
    fn encrypt_body(&self, data: &mut [u8]) -> Result<Vec<u8>, SimpleSecretsError> {
        let mut iv = self.env.iv()?.into();
        let mut nonce = self.env.nonce()?.into();

        let cipherdata = self
            .master_key
            .sender_cipher()
            .encrypt(&iv, &nonce, &data)?;

        nonce.zeroize();
        iv.zeroize();
        data.zeroize();

        Ok(cipherdata)
    }
}

impl<E: Env> From<[u8; 32]> for Packet<E> {
    /// Construct a Packet with the given 256-bit master key.
    fn from(master_key: [u8; 32]) -> Self {
        Packet {
            master_key: master_key.into(),
            env: Env::new().unwrap(),
        }
    }
}

//
// Module Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    macro_rules! roundtrip {
        ($name:ident, $ty:ty) => {
            quickcheck! {
                fn $name(expected: $ty) -> bool {
                    let packet: Packet = [0x07; 32].into();

                    if let Ok(token) = packet.pack(&expected) {
                        packet.unpack(token).map(|actual: $ty| {
                            actual == expected
                        }).unwrap_or_default()
                    } else {
                        false
                    }
                }
            }
        };
    }

    roundtrip!(test_u32_round_trip, u32);
    roundtrip!(test_u64_round_trip, u64);
    roundtrip!(test_string_round_trip, String);
    roundtrip!(test_bytes_round_trip, Vec<u8>);
    roundtrip!(test_hashmap_round_trip, std::collections::HashMap<usize, usize>);

    quickcheck! {
        fn test_key_parse_no_crashes(key: String) -> bool {
            let _ = Packet::new(key);
            true
        }
    }

    quickcheck! {
        fn test_unpack_no_crashes(input: String) -> bool {
            let packet: Packet = [0x07; 32].into();
            let _ : Result<usize, _> = packet.unpack(input);
            true
        }
    }

    #[test]
    #[allow(unused_variables)]
    fn it_should_accept_64char_hex() -> Result<(), SimpleSecretsError> {
        let key = [0xbc; 32];
        let hex = data_encoding::HEXLOWER_PERMISSIVE.encode(&key);
        Packet::new(hex)?;
        Ok(())
    }

    #[test]
    #[should_panic]
    fn it_should_only_accept_hex() {
        Packet::new("not-a-hex-string").unwrap();
    }

    #[test]
    #[should_panic]
    fn it_should_only_accept_64char_hex() {
        Packet::new("1dad").unwrap();
    }

    quickcheck! {
        fn test_websafe_strings(input: Vec<u8>) -> bool {
            let packet: Packet = [0x07; 32].into();
            let token = packet.pack(&input).unwrap();
            token.chars().all(|c| {
                ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_'
            })
        }
    }

    quickcheck! {
        fn test_different_packets(input: Vec<u8>) -> bool {
            let a: Packet = [0x07; 32].into();
            let b: Packet = [0x08; 32].into();
            let token = a.pack(&input).unwrap();
            b.unpack::<Vec<u8>, String>(token).is_err()
        }
    }
}

//
// Cross-language compatibility tests
//

#[cfg(test)]
mod compatibility {
    use super::*;
    use data_encoding::HEXLOWER;

    struct TestEnv();

    impl Env for TestEnv {
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

    fn compat_sender() -> Result<Packet<TestEnv>, SimpleSecretsError> {
        let key = "eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
        Packet::with_env(key, TestEnv())
    }

    mod string {
        use super::*;

        static COMPAT_STRING: &str = "This is the simple-secrets compatibility standard string.";
        static WEBSAFE_MSGPACK_1: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0";
        static WEBSAFE_MSGPACK_5: &str = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNp54eHe8KRY2JqOo9H8bi3Hnm4G0-r5SNlXXhIW9S99qTxTwibKW7mLkaNMTeZ1ktDwx-4sjCpCnXPIyZe7-l6-o6XjIqazRdhGD6AH5ZS9UFqLpaqIowSUQ9CeiQeFBQ";

        #[test]
        fn it_creates_packets_from_strings() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let packet = sender.pack(COMPAT_STRING)?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_strings() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let output: String = sender.unpack(WEBSAFE_MSGPACK_1)?;
            assert_eq!(output, COMPAT_STRING);
            let output: String = sender.unpack(WEBSAFE_MSGPACK_5)?;
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
            let sender = compat_sender()?;
            let packet = sender.pack(&compat_bytes())?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_bytes() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let output: ByteBuf = sender.unpack(WEBSAFE_MSGPACK_1)?;
            assert_eq!(output, compat_bytes());
            let output: ByteBuf = sender.unpack(WEBSAFE_MSGPACK_5)?;
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
            let sender = compat_sender()?;
            let packet = sender.pack(&COMPAT_NUMBER)?;
            assert_eq!(packet, WEBSAFE_MSGPACK_1);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_numbers() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let output: u16 = sender.unpack(WEBSAFE_MSGPACK_1)?;
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
            let sender = compat_sender()?;
            let unit = ();
            let packet = sender.pack(&unit)?;
            assert_eq!(packet, WEBSAFE_MSGPACK_1);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_nil() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let output: () = sender.unpack(WEBSAFE_MSGPACK_1)?;
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
            arr.push("This is the simple-secrets compatibility standard array.".to_owned());
            arr.push("This is the simple-secrets compatibility standard array.".to_owned());
            arr
        }

        #[test]
        fn it_creates_packets_from_an_array() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let packet = sender.pack(&compat_array())?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_an_array() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let output: Vec<String> = sender.unpack(WEBSAFE_MSGPACK_1)?;
            assert_eq!(output, compat_array());
            let output: Vec<String> = sender.unpack(WEBSAFE_MSGPACK_5)?;
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
            arr.insert(
                "compatibility-key".to_owned(),
                "This is the simple-secrets compatibility standard map.".to_owned(),
            );
            arr
        }

        #[test]
        fn it_creates_packets_from_a_map() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let packet = sender.pack(&compat_map())?;
            assert_eq!(packet, WEBSAFE_MSGPACK_5);
            Ok(())
        }

        #[test]
        fn it_recovers_packets_from_a_map() -> Result<(), SimpleSecretsError> {
            let sender = compat_sender()?;
            let output: HashMap<String, String> = sender.unpack(WEBSAFE_MSGPACK_1)?;
            assert_eq!(output, compat_map());
            let output: HashMap<String, String> = sender.unpack(WEBSAFE_MSGPACK_5)?;
            assert_eq!(output, compat_map());
            Ok(())
        }
    }
}
