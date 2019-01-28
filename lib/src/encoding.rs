use crate::error::SimpleSecretsError;
use data_encoding::BASE64URL_NOPAD;
use rmp_serde::{Deserializer, Serializer};
use serde::Deserialize;
use serde::Serialize;

/// Turn a websafe string back into a binary buffer.
///
/// Uses base64url encoding.
pub fn binify<T: AsRef<str>>(string: T) -> Result<Vec<u8>, SimpleSecretsError> {
    Ok(BASE64URL_NOPAD
        .decode(string.as_ref().as_bytes())
        .map_err(|e| SimpleSecretsError::TextDecodingError {
            role: "packet",
            cause: e,
        })?)
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
pub fn serialize<T: ?Sized>(value: &T) -> Result<Vec<u8>, SimpleSecretsError>
where
    T: Serialize,
{
    let mut buf = vec![];
    value.serialize(&mut Serializer::new(&mut buf))?;
    Ok(buf)
}

/// Turn a binary representation into a Rust structure
/// suitable for use in application logic. This object
/// possibly originated in a different programming
/// environment—it should be JSON-like in structure.
///
/// Uses serde for deserialization from MsgPack format.
pub fn deserialize<'a, 'b, T>(v: &'a [u8]) -> Result<T, SimpleSecretsError>
where
    T: Deserialize<'b>,
{
    let mut de = Deserializer::new(v);
    Ok(Deserialize::deserialize(&mut de)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn it_should_binify_from_a_string() {
        let val = binify("cartinir90_-");
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
        let binary = serialize(text).unwrap();
        let actual: String = deserialize(&binary).unwrap();
        assert_eq!("abcd", actual);
        let binary = serialize(&arr).unwrap();
        let actual: [i32; 10] = deserialize(&binary).unwrap();
        assert_eq!([0x32; 10], actual);
    }
}
