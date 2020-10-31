# digest-access
HTTP Digest Access Authentication for Rust

A (mostly) complete implementation of ITEF RFC2069, RFC2617 and RFC7616

Features
---

* `from-headers` - provides the DigestAccess::from_headers function to 
  create a DigetAccess instance from HTTP response headers.
  Adds the `http` crate as a dependency.

License
---
Digest Access is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](LICENSE-MIT))

at your option.
