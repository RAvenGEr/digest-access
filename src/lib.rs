//! This crate provides HTTP Digest Access Authentication, as specified by ITEF RFC2069, RFC2617 and RFC7616
//!

mod digest_authenticator;

pub use digest_authenticator::{DigestAccess, DigestParseError};

#[cfg(test)]
mod tests {

    #[test]
    fn rfc2069() {
        let rfc2069_test = r#"Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let mut d = rfc2069_test
            .parse::<crate::digest_authenticator::DigestAccess>()
            .unwrap();
        d.set_username("Mufasa");
        d.set_password("CircleOfLife");
        let auth_str = d.generate_authorization("GET", "/dir/index.html", None, None);
        assert_eq!(
            auth_str.unwrap(),
            r#"Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", response="1949323746fe6a43ef61f9606e7febea", opaque="5ccc069c403ebaf9f0171e9517f40e41""#
        );
    }

    #[test]
    fn rfc2617() {
        let rfc2617_test = r#"Digest realm="testrealm@host.com", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let mut d = rfc2617_test
            .parse::<crate::digest_authenticator::DigestAccess>()
            .unwrap();
        d.set_username("Mufasa");
        d.set_password("Circle Of Life");
        let auth_str = d.generate_authorization("GET", "/dir/index.html", None, Some("0a4f113b"));
        assert_eq!(
            auth_str.unwrap(),
            r#"Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth, algorithm=MD5, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1", opaque="5ccc069c403ebaf9f0171e9517f40e41""#
        );
    }

    #[test]
    fn rfc7616_md5() {
        let rfc7616_test = r#"Digest
        realm="http-auth@example.org",
        qop="auth, auth-int",
        algorithm=MD5,
        nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
        opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#;

        let mut d = rfc7616_test
            .parse::<crate::digest_authenticator::DigestAccess>()
            .unwrap();
        d.set_username("Mufasa");
        d.set_password("Circle of Life");
        let auth_str = d.generate_authorization(
            "GET",
            "/dir/index.html",
            None,
            Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"),
        );

        assert_eq!(
            auth_str.unwrap(),
            r#"Digest username="Mufasa", realm="http-auth@example.org", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", uri="/dir/index.html", qop=auth, algorithm=MD5, nc=00000001, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", response="8ca523f5e9506fed4657c9700eebdbec", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#
        );
    }

    #[test]
    fn rfc7616_sha256() {
        let rfc7616_test = r#"Digest
        realm="http-auth@example.org",
        qop="auth, auth-int",
        algorithm=SHA-256,
        nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
        opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#;

        let mut d = rfc7616_test
            .parse::<crate::digest_authenticator::DigestAccess>()
            .unwrap();
        d.set_username("Mufasa");
        d.set_password("Circle of Life");
        let auth_str = d.generate_authorization(
            "GET",
            "/dir/index.html",
            None,
            Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"),
        );

        assert_eq!(
            auth_str.unwrap(),
            r#"Digest username="Mufasa", realm="http-auth@example.org", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", uri="/dir/index.html", qop=auth, algorithm=SHA-256, nc=00000001, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#
        );
    }

    #[test]
    fn rfc7616_userhash_512_256() {
        let rfc7616_test = r#"Digest
        realm="api@example.org",
        qop="auth",
        algorithm=SHA-512-256,
        nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
        opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
        charset=UTF-8,
        userhash=true"#;

        let mut d = rfc7616_test
            .parse::<crate::digest_authenticator::DigestAccess>()
            .unwrap();
        d.set_username("Jäsøn Doe");
        d.set_password("Secret, or not?");
        let auth_str = d.generate_authorization(
            "GET",
            "/doe.json",
            None,
            Some("NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v"),
        );

        // Expected results from erata page
        assert_eq!(
            auth_str.unwrap(),
            r#"Digest username="793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b", realm="api@example.org", nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", uri="/doe.json", qop=auth, algorithm=SHA-512-256, nc=00000001, cnonce="NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", response="3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5", opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS", userhash=true"#
        );
    }

    #[test]
    #[cfg(feature = "from-headers")]
    fn from_headers() {
        const WWW_AUTH_VALUE: &str = r#"Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093""#;
        let mut headers = http::HeaderMap::new();
        let r = crate::digest_authenticator::DigestAccess::from_headers(&headers);
        assert!(r.is_err());
        headers.insert(http::header::WWW_AUTHENTICATE, WWW_AUTH_VALUE.parse().unwrap());
        let r = crate::digest_authenticator::DigestAccess::from_headers(&headers);
        assert!(r.is_ok());
    }
}
