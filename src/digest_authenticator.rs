use digest::Digest;
use md5::Md5;
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;
use sha2::{Sha256, Sha512Trunc256};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
enum DigestAlgorithm {
    MD5,
    SHA256,
    SHA512_256,
}

impl DigestAlgorithm {
    fn to_str(&self) -> &'static str {
        match self {
            DigestAlgorithm::MD5 => "MD5",
            DigestAlgorithm::SHA256 => "SHA-256",
            DigestAlgorithm::SHA512_256 => "SHA-512-256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum QualityOfProtection {
    None, // rfc2069
    Auth,
    AuthInt,
}

impl QualityOfProtection {
    fn to_str(self) -> &'static str {
        match self {
            QualityOfProtection::Auth => "auth",
            QualityOfProtection::AuthInt => "auth-int",
            QualityOfProtection::None => "",
        }
    }
}

#[derive(Debug)]
struct QualityOfProtectionData {
    cnonce: String,
    count_str: String,
    qop: QualityOfProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestParseError {
    Empty,
    MissingDigest,
    MissingRealm,
    MissingNonce,
}

impl DigestParseError {
    fn description(&self) -> &str {
        match self {
            DigestParseError::Empty => "cannot parse Digest scheme from empty string",
            DigestParseError::MissingDigest => "string does not start with \"Digest \"",
            DigestParseError::MissingNonce => "Digest scheme must contain a nonce value",
            DigestParseError::MissingRealm => "Digest scheme must contain a realm value",
        }
    }
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.description().fmt(f)
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct StrPosition {
    start: usize,
    end: usize,
}

impl StrPosition {
    fn to_str<'a>(&self, s: &'a str) -> &'a str {
        &s[self.start..self.end]
    }

    fn is_valid(&self) -> bool {
        self.start < self.end
    }
}

#[derive(Debug)]
pub struct DigestAccess {
    www_authenticate: String,
    nonce: StrPosition,
    domain: Option<Vec<StrPosition>>,
    realm: StrPosition,
    opaque: StrPosition,
    stale: bool,
    nonce_count: u32,
    algorithm: DigestAlgorithm,
    session: bool,
    userhash: bool,
    qop: QualityOfProtection,
    qop_data: Option<QualityOfProtectionData>,
}

impl FromStr for DigestAccess {
    type Err = DigestParseError;

    fn from_str(auth: &str) -> Result<Self, Self::Err> {
        if auth.is_empty() {
            return Err(DigestParseError::Empty);
        }

        if &auth[..6].to_lowercase() != "digest" {
            return Err(DigestParseError::MissingDigest);
        }

        let mut res = Self {
            www_authenticate: auth.to_owned(),
            nonce: StrPosition::default(),
            domain: None,
            realm: StrPosition::default(),
            opaque: StrPosition::default(),
            stale: false,
            nonce_count: 0,
            algorithm: DigestAlgorithm::MD5,
            session: false,
            userhash: false,

            qop: QualityOfProtection::None,
            qop_data: None,
        };

        #[derive(PartialEq)]
        enum KeyVal {
            PreKey,
            Key,
            PreVal,
            QuoteVal,
            Val,
        }

        let mut state = KeyVal::PreKey;
        let mut key: &str = "";
        let mut k_pos = StrPosition::default();
        let mut v_pos = StrPosition::default();

        for ch_ind in auth.char_indices().skip(6) {
            match state {
                KeyVal::PreKey => {
                    if !ch_ind.1.is_ascii_whitespace() {
                        k_pos.start = ch_ind.0;
                        state = KeyVal::Key;
                    }
                }
                KeyVal::Key => {
                    if ch_ind.1 != '=' {
                        continue;
                    }
                    k_pos.end = ch_ind.0;
                    key = k_pos.to_str(auth);
                    state = KeyVal::PreVal;
                    k_pos = StrPosition::default();
                }
                KeyVal::PreVal => {
                    if ch_ind.1 == '"' {
                        v_pos.start = ch_ind.0 + 1;
                        state = KeyVal::QuoteVal;
                    } else {
                        v_pos.start = ch_ind.0;
                        state = KeyVal::Val;
                    }
                }
                KeyVal::QuoteVal => {
                    if ch_ind.1 != '"' {
                        continue;
                    }
                    v_pos.end = ch_ind.0;
                    let is_last = ch_ind.0 == auth.len() - 1;
                    if is_last {
                        res.process_header_value(&key, auth, v_pos);
                    }
                    state = KeyVal::Val;
                }
                KeyVal::Val => {
                    let is_last = ch_ind.0 == auth.len() - 1;
                    if !is_last && ch_ind.1 != ',' {
                        if v_pos.end == 0 && ch_ind.1.is_ascii_whitespace() {
                            v_pos.end = ch_ind.0;
                        }
                        continue;
                    }
                    if v_pos.end == 0 {
                        v_pos.end = ch_ind.0;
                    }
                    if is_last {
                        v_pos.end = ch_ind.0 + 1;
                    }
                    res.process_header_value(&key, auth, v_pos);
                    v_pos = StrPosition::default();
                    state = KeyVal::PreKey;
                }
            }
        }

        match (res.nonce.is_valid(), res.realm.is_valid()) {
            (true, true) => Ok(res),
            (true, false) => Err(DigestParseError::MissingRealm),
            (_, _) => Err(DigestParseError::MissingNonce),
        }
    }
}

impl DigestAccess {
    ///
    pub fn generate_authentication(
        &mut self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
        cnonce: Option<&str>,
    ) -> String {
        self.qop_data = if self.qop != QualityOfProtection::None {
            let cnonce = match cnonce {
                Some(c) => c.to_owned(),
                None => Self::cnonce(),
            };
            self.nonce_count += 1;
            let count_str = format!("{:08.x}", self.nonce_count);
            let qop = if self.qop == QualityOfProtection::AuthInt && body.is_none() {
                QualityOfProtection::Auth
            } else {
                self.qop
            };
            Some(QualityOfProtectionData {
                cnonce,
                count_str,
                qop,
            })
        } else {
            None
        };
        let response = match self.algorithm {
            DigestAlgorithm::MD5 => {
                self.generate_response_string::<Md5>(username, password, method, uri, body)
            }
            DigestAlgorithm::SHA256 => {
                self.generate_response_string::<Sha256>(username, password, method, uri, body)
            }
            DigestAlgorithm::SHA512_256 => self
                .generate_response_string::<Sha512Trunc256>(username, password, method, uri, body),
        };
        let mut auth_str_len = 90
            + username.len()
            + self.realm().len()
            + self.nonce().len()
            + uri.len()
            + response.len();
        if self.qop != QualityOfProtection::None {
            let qop_data = self.qop_data.as_ref().unwrap();
            auth_str_len +=
                6 + qop_data.qop.to_str().len() + qop_data.count_str.len() + qop_data.cnonce.len();
        }
        if let Some(o) = self.opaque() {
            auth_str_len += 11 + o.len();
        }
        if self.userhash {
            auth_str_len += 15 + 64;
        }
        let mut auth = String::with_capacity(auth_str_len);
        auth.push_str("Digest username=\"");
        if self.userhash {
            let user = match self.algorithm {
                DigestAlgorithm::MD5 => self.hash_username::<Md5>(username),
                DigestAlgorithm::SHA256 => self.hash_username::<Sha256>(username),
                DigestAlgorithm::SHA512_256 => self.hash_username::<Sha512Trunc256>(username),
            };
            auth.push_str(&user);
        } else {
            auth.push_str(username);
        }
        auth.push_str("\", realm=\"");
        auth.push_str(self.realm());
        auth.push_str("\", nonce=\"");
        auth.push_str(self.nonce());
        auth.push_str("\", uri=\"");
        auth.push_str(uri);
        if self.qop != QualityOfProtection::None {
            let qop_data = self.qop_data.as_ref().unwrap();
            auth.push_str("\", qop=");
            auth.push_str(qop_data.qop.to_str());
            auth.push_str(", algorithm=");
            auth.push_str(self.algorithm.to_str());
            auth.push_str(", nc=");
            auth.push_str(&qop_data.count_str);
            auth.push_str(", cnonce=\"");
            auth.push_str(&qop_data.cnonce);
        }
        auth.push_str("\", response=\"");
        auth.push_str(&response);
        if let Some(o) = self.opaque() {
            auth.push_str("\", opaque=\"");
            auth.push_str(o);
        }
        auth.push('"');
        if self.userhash {
            auth.push_str(", userhash=true");
        }
        auth
    }

    fn process_header_value(&mut self, key: &str, auth: &str, val_pos: StrPosition) {
        if key.eq_ignore_ascii_case("nonce") {
            self.nonce = val_pos;
        } else if key.eq_ignore_ascii_case("realm") {
            self.realm = val_pos;
        } else if key.eq_ignore_ascii_case("domain") {
            // @todo solve splitting - this isn't commonly used
            // res.domain = Some(value.as_str().split(' ').collect());
        } else if key.eq_ignore_ascii_case("opaque") {
            self.opaque = val_pos;
        } else if key.eq_ignore_ascii_case("stale")
            && val_pos.to_str(auth).eq_ignore_ascii_case("true")
        {
            self.stale = true;
        } else if key.eq_ignore_ascii_case("algorithm") {
            let alg_str = val_pos.to_str(auth).to_lowercase();
            if alg_str.contains("sha-256") {
                self.algorithm = DigestAlgorithm::SHA256;
                if alg_str.contains("sha-256-sess") {
                    self.session = true;
                }
            } else if alg_str.contains("sha-512-256") {
                self.algorithm = DigestAlgorithm::SHA512_256;
                if alg_str.contains("sha-512-256-sess") {
                    self.session = true;
                }
            } else if alg_str.contains("md5-sess") {
                self.session = true;
            }
        } else if key.eq_ignore_ascii_case("qop") {
            let qop_str = val_pos.to_str(auth);
            if qop_str.contains(QualityOfProtection::AuthInt.to_str())
                || qop_str.eq_ignore_ascii_case(QualityOfProtection::AuthInt.to_str())
            {
                self.qop = QualityOfProtection::AuthInt;
            } else {
                self.qop = QualityOfProtection::Auth;
            }
        } else if key.eq_ignore_ascii_case("userhash")
            && val_pos.to_str(auth).eq_ignore_ascii_case("true")
        {
            self.userhash = true;
        }
    }

    fn realm(&self) -> &str {
        self.realm.to_str(&self.www_authenticate)
    }

    pub fn nonce(&self) -> &str {
        self.nonce.to_str(&self.www_authenticate)
    }

    fn opaque(&self) -> Option<&str> {
        if self.opaque.is_valid() {
            Some(self.opaque.to_str(&self.www_authenticate))
        } else {
            None
        }
    }

    fn cnonce() -> String {
        let mut rng = thread_rng();
        let len = Uniform::new_inclusive(8, 32);
        let val = Uniform::new_inclusive(0, 15);
        let mut cnonce = String::with_capacity(len.sample(&mut rng));
        let hex_vals = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        while cnonce.len() < cnonce.capacity() {
            cnonce.push(hex_vals[val.sample(&mut rng)]);
        }
        cnonce
    }

    fn calculate_ha1<T: Digest>(&self, username: &str, password: &str) -> String {
        let mut hasher = T::new();
        hasher.update(username);
        hasher.update(":");
        hasher.update(self.realm());
        hasher.update(":");
        hasher.update(password);
        if self.session {
            let qop_data = self.qop_data.as_ref().unwrap();
            let digest = hasher.finalize_reset();
            hasher.update(digest);
            hasher.update(":");
            hasher.update(self.nonce());
            hasher.update(":");
            hasher.update(&qop_data.cnonce);
        }
        let digest = hasher.finalize();
        hex::encode(digest)
    }

    fn calculate_ha2<T: Digest>(&self, method: &str, uri: &str, body: Option<&str>) -> String {
        let mut hasher = T::new();
        hasher.update(method);
        hasher.update(":");
        hasher.update(uri);
        if self.qop != QualityOfProtection::None
            && self.qop_data.as_ref().unwrap().qop == QualityOfProtection::AuthInt
        {
            hasher.update(":");
            let mut body_hasher = T::new();
            body_hasher.update(body.unwrap());
            hasher.update(hex::encode(body_hasher.finalize()));
        }
        let digest = hasher.finalize();
        hex::encode(digest)
    }

    fn calculate_response<T: Digest>(&self, ha1: &str, ha2: &str) -> String {
        let mut hasher = T::new();
        hasher.update(ha1);
        hasher.update(":");
        hasher.update(self.nonce());
        hasher.update(":");
        if self.qop != QualityOfProtection::None {
            let qop_data = self.qop_data.as_ref().unwrap();
            hasher.update(&qop_data.count_str);
            hasher.update(":");
            hasher.update(&qop_data.cnonce);
            hasher.update(":");
            hasher.update(qop_data.qop.to_str());
            hasher.update(":");
        }
        hasher.update(ha2);
        let digest = hasher.finalize();
        hex::encode(digest)
    }

    fn generate_response_string<T: Digest>(
        &self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> String {
        let ha1 = self.calculate_ha1::<T>(username, password);

        let ha2 = self.calculate_ha2::<T>(method, uri, body);

        self.calculate_response::<T>(&ha1, &ha2)
    }

    fn hash_username<T: Digest>(&self, username: &str) -> String {
        let mut hasher = T::new();
        hasher.update(username);
        hasher.update(":");
        hasher.update(self.realm());
        hex::encode(hasher.finalize())
    }
}
