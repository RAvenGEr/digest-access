[![crates.io](https://img.shields.io/crates/v/digest-access.svg)](https://crates.io/crates/digest-access)
[![docs.rs](https://docs.rs/digest-access/badge.svg)](https://docs.rs/digest-access)

# digest-access
HTTP Digest Access Authentication for Rust

A (mostly) complete implementation of ITEF RFC2069, RFC2617 and RFC7616

## Features

* `from-headers` - provides an implementation of the `TryFrom<http::HeaderMap>` trait to 
  create a DigestAccess instance from HTTP response headers. See the reqwest_get example for how to use.

  Adds the `http` crate as a dependency.

## License

Digest Access is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](LICENSE-MIT))

at your option.
