#![allow(dead_code)]

use ref_thread_local::*;
use simple_secrets::Sender;

ref_thread_local! {
    static managed SENDER: Sender = Sender::new("eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad").unwrap();
}

pub fn test_unpack(token: String) -> bool {
    SENDER.borrow().unpack_raw(token).is_ok()
}

pub fn test_roundtrip(bytes: Vec<u8>) -> bool {
    let sender = SENDER.borrow();
    let token = sender.pack_raw(&mut bytes.clone()).unwrap();
    let actual = sender.unpack_raw(token).unwrap();
    assert_eq!(bytes, actual);
    true
}
