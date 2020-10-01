# digest-access
HTTP Digest Access Authentication for Rust

A (mostly) complete implementation of ITEF RFC2069, RFC2617 and RFC7616

Features
---

* `from-headers` - provides the digest_authenticate_from_headers function to 
  extract a Digest Access Authentication WWW-Authenticate string from an HTTP
  response. Adds the `http` crate as a dependency.

License
---
Digest Access is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](LICENSE-MIT))

at your option.
