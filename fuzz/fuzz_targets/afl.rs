#[macro_use]
extern crate afl;

mod simple_secrets;

fn main() {
    fuzz!(|data: String| {
        simple_secrets::test_unpack(data);
    });
}
