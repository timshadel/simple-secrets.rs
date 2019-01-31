#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

mod simple_secrets;

fuzz_target!(|data: String| {
    simple_secrets::test_unpack(data);
});
