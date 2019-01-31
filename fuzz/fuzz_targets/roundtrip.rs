#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

mod simple_secrets;

fuzz_target!(|data: Vec<u8>| {
    simple_secrets::test_roundtrip(data);
});
