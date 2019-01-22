
# simple-secrets.rs [![Build Status](https://travis-ci.org/timshadel/simple-secrets.rs.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets.rs)

The Rust implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages: [Node.js][simple-secrets], [Ruby][simple-secrets.rb], [Rust][simple-secrets.rs], [Objective-C][SimpleSecrets], [Java][simple-secrets.java], [Erlang][simple_secrets.erl].

[simple-secrets]: https://github.com/timshadel/simple-secrets
[simple-secrets.rb]: https://github.com/timshadel/simple-secrets.rb
[simple-secrets.rs]: https://github.com/timshadel/simple-secrets.rs
[SimpleSecrets]: https://github.com/timshadel/SimpleSecrets
[simple-secrets.java]: https://github.com/timshadel/simple-secrets.java
[simple_secrets.erl]: https://github.com/CamShaft/simple_secrets.erl

## Examples

### Basic

Send:

```rust
use simple_secrets::Packet;

// Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
let sender = Packet::new("<64-char hex string master key (32 bytes, 256 bits)>".to_string());
let packet = sender.pack("this is a secret message").unwrap();
// => 'Qr4m7AughkcQIRqQvlyXiB67EwHdBf5n9JD2s_Z9NpO4ksPGvLYjNbDm3HRzvFXFSpV2IqDQw_LTamndMh2c7iOQT0lSp4LstqJPAtoQklU5sb7JHYyTOuf-6W-q7W8gAnq1wCs5'
```

```rust
// Initialize from any [u8; 32] if your key is already in bytes
let sender = Packet::from([0x9f; 32]);
```

Receive:

```rust
use simple_secrets::Packet;

// Same shared key
let sender = Packet::new("<64-char hex string master key (32 bytes, 256 bits)>".to_string());
// Read data from somewhere
let packet = "OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM".to_string();
let secret_message = sender.unpack(packet)?;
// => { "msg" => "this is a secret message" }
```


## Can you add ...

This implementation follows [simple-secrets] for 100% compatibility.

## License 

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
