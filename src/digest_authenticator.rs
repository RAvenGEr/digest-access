use digest::{Digest, Output};
use md5::Md5;
use rand::{
    distributions::{Distribution, Uniform},
    seq::SliceRandom,
    thread_rng,
};
use sha2::{Sha256, Sha512_256};
use std::{fmt, ops::Range, str::FromStr};

#[cfg(feature = "from-headers")]
use http::{header::WWW_AUTHENTICATE, HeaderMap};
#[cfg(feature = "from-headers")]
use std::convert::TryFrom;

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
    Length,
    InvalidEncoding,
    MissingDigest,
    MissingRealm,
    MissingNonce,
}

impl DigestParseError {
    fn description(&self) -> &str {
        match self {
            DigestParseError::Length => "Cannot parse Digest scheme from short string.",
            DigestParseError::InvalidEncoding => "String doesn't match expected encoding.",
            DigestParseError::MissingDigest => "String does not start with \"Digest \"",
            DigestParseError::MissingNonce => "Digest scheme must contain a nonce value.",
            DigestParseError::MissingRealm => "Digest scheme must contain a realm value.",
        }
    }
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.description().fmt(f)
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct StrRange {
    start: usize,
    end: usize,
}

impl StrRange {
    fn is_valid(&self) -> bool {
        self.start < self.end
    }
}

impl Into<Range<usize>> for StrRange {
    fn into(self) -> Range<usize> {
        self.start..self.end
    }
}

#[derive(Debug)]
pub struct DigestAccess {
    authenticate: String,
    nonce: StrRange,
    domain: Vec<StrRange>,
    realm: StrRange,
    opaque: StrRange,
    stale: bool,
    nonce_count: u32,
    algorithm: DigestAlgorithm,
    session: bool,
    userhash: bool,
    qop: QualityOfProtection,
    qop_data: Option<QualityOfProtectionData>,
    username: Option<String>,
    hashed_user_realm_pass: Option<Vec<u8>>,
}

impl FromStr for DigestAccess {
    type Err = DigestParseError;

    fn from_str(auth: &str) -> Result<Self, Self::Err> {
        if auth.len() < Self::MIN_AUTH_LENGTH {
            Err(DigestParseError::Length)
        } else {
            Self::create_from_www_auth(auth)
        }
    }
}

impl DigestAccess {
    const MIN_AUTH_LENGTH: usize = 22;

    pub fn set_username<A: Into<String>>(&mut self, username: A) {
        self.username = Some(username.into());
    }

    pub fn set_password(&mut self, password: &str) {
        if let Some(user) = self.username.as_ref() {
            let hashed = match self.algorithm {
                DigestAlgorithm::MD5 => {
                    Self::hash_user_realm_password::<Md5>(user, self.realm(), password).to_vec()
                }
                DigestAlgorithm::SHA256 => {
                    Self::hash_user_realm_password::<Sha256>(user, self.realm(), password).to_vec()
                }
                DigestAlgorithm::SHA512_256 => {
                    Self::hash_user_realm_password::<Sha512_256>(user, self.realm(), password)
                        .to_vec()
                }
            };
            self.hashed_user_realm_pass = Some(hashed);
        }
    }

    pub fn set_hashed_user_realm_password<A: Into<Vec<u8>>>(&mut self, hashed: A) {
        self.hashed_user_realm_pass = Some(hashed.into());
    }

    /// Generate the Authorization header value
    pub fn generate_authorization(
        &mut self,
        method: &str,
        uri: &str,
        body: Option<&[u8]>,
        cnonce: Option<&str>,
    ) -> Option<String> {
        if self.username.is_none() || self.hashed_user_realm_pass.is_none() {
            return None;
        }

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
            DigestAlgorithm::MD5 => self.generate_response_string::<Md5>(
                self.hashed_user_realm_pass.as_ref().unwrap(),
                method,
                uri,
                body,
            ),
            DigestAlgorithm::SHA256 => self.generate_response_string::<Sha256>(
                self.hashed_user_realm_pass.as_ref().unwrap(),
                method,
                uri,
                body,
            ),
            DigestAlgorithm::SHA512_256 => self.generate_response_string::<Sha512_256>(
                self.hashed_user_realm_pass.as_ref().unwrap(),
                method,
                uri,
                body,
            ),
        };
        let username = self.username.as_ref().unwrap();
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
                DigestAlgorithm::SHA512_256 => self.hash_username::<Sha512_256>(username),
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
        Some(auth)
    }

    fn create_from_www_auth(auth: &str) -> Result<Self, DigestParseError> {
        let input = Self::digest_challenge(auth)?;
        let mut res = Self {
            authenticate: input.to_owned(),
            nonce: StrRange::default(),
            domain: Vec::new(),
            realm: StrRange::default(),
            opaque: StrRange::default(),
            stale: false,
            nonce_count: 0,
            algorithm: DigestAlgorithm::MD5,
            session: false,
            userhash: false,
            qop: QualityOfProtection::None,
            qop_data: None,
            username: None,
            hashed_user_realm_pass: None,
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
        let mut key = StrRange::default();
        let mut value = StrRange::default();

        for (idx, ch) in input.char_indices() {
            match state {
                KeyVal::PreKey => {
                    if !ch.is_ascii_whitespace() {
                        key.start = idx;
                        state = KeyVal::Key;
                    }
                }
                KeyVal::Key => {
                    if ch != '=' {
                        continue;
                    }
                    key.end = idx;
                    state = KeyVal::PreVal;
                }
                KeyVal::PreVal => {
                    if ch == '"' {
                        value.start = idx + 1;
                        state = KeyVal::QuoteVal;
                    } else {
                        value.start = idx;
                        state = KeyVal::Val;
                    }
                }
                KeyVal::QuoteVal => {
                    if ch != '"' {
                        continue;
                    }
                    value.end = idx;
                    let is_last = idx == input.len() - 1;
                    if is_last {
                        res.apply_directive(key, value);
                    }
                    state = KeyVal::Val;
                }
                KeyVal::Val => {
                    let is_last = idx == input.len() - 1;
                    if !is_last && ch != ',' {
                        if value.end == 0 && ch.is_ascii_whitespace() {
                            value.end = idx;
                        }
                        continue;
                    }
                    if value.end == 0 {
                        value.end = idx;
                    }
                    if is_last {
                        value.end = idx + 1;
                    }
                    res.apply_directive(key, value);
                    value = StrRange::default();
                    key = StrRange::default();
                    state = KeyVal::PreKey;
                }
            }
        }

        match (res.nonce.is_valid(), res.realm.is_valid()) {
            (_, false) => Err(DigestParseError::MissingRealm),
            (false, _) => Err(DigestParseError::MissingNonce),
            (true, true) => Ok(res),
        }
    }

    #[inline(always)]
    fn digest_challenge(input: &str) -> Result<&str, DigestParseError> {
        if input.is_char_boundary(6) {
            let (dig, input) = input.split_at(6);
            if dig.eq_ignore_ascii_case("digest") {
                let ret = input.trim_start_matches(|c: char| c.is_ascii_whitespace());
                if input.len() == ret.len() {
                    Err(DigestParseError::InvalidEncoding)
                } else {
                    Ok(ret)
                }
            } else {
                Err(DigestParseError::MissingDigest)
            }
        } else {
            Err(DigestParseError::InvalidEncoding)
        }
    }

    fn apply_directive(&mut self, key: StrRange, val: StrRange) {
        let key = self.authenticate_slice(key.into());
        if key.eq_ignore_ascii_case("nonce") {
            self.nonce = val;
        } else if key.eq_ignore_ascii_case("realm") {
            self.realm = val;
        } else if key.eq_ignore_ascii_case("domain") {
            // @todo solve splitting - this isn't commonly used
            // res.domain = Some(value.as_str().split(' ').collect());
        } else if key.eq_ignore_ascii_case("opaque") {
            self.opaque = val;
        } else if key.eq_ignore_ascii_case("stale")
            && self
                .authenticate_slice(val.into())
                .eq_ignore_ascii_case("true")
        {
            self.stale = true;
        } else if key.eq_ignore_ascii_case("algorithm") {
            let alg_str = self.authenticate_slice(val.into()).to_ascii_lowercase();
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
            let qop_str = self.authenticate_slice(val.into()).to_ascii_lowercase();
            if qop_str.contains(QualityOfProtection::AuthInt.to_str()) {
                self.qop = QualityOfProtection::AuthInt;
            } else {
                self.qop = QualityOfProtection::Auth;
            }
        } else if key.eq_ignore_ascii_case("userhash")
            && self
                .authenticate_slice(val.into())
                .eq_ignore_ascii_case("true")
        {
            self.userhash = true;
        }
    }

    #[inline(always)]
    fn authenticate_slice(&self, r: Range<usize>) -> &str {
        &self.authenticate[r]
    }

    fn realm(&self) -> &str {
        self.authenticate_slice(self.realm.into())
    }

    pub fn nonce(&self) -> &str {
        self.authenticate_slice(self.nonce.into())
    }

    fn opaque(&self) -> Option<&str> {
        if self.opaque.is_valid() {
            Some(self.authenticate_slice(self.opaque.into()))
        } else {
            None
        }
    }

    pub fn cnonce() -> String {
        const HEX_CHARS: [char; 16] = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        let mut rng = thread_rng();
        let size = Uniform::new_inclusive(8, 32).sample(&mut rng);
        let mut cnonce = String::with_capacity(size);
        for _ in 0..size {
            cnonce.push(*HEX_CHARS.choose(&mut rng).unwrap());
        }
        cnonce
    }

    pub fn hash_user_realm_password<T: Digest>(
        username: &str,
        realm: &str,
        password: &str,
    ) -> Output<T> {
        let mut hasher = T::new();
        hasher.update(username);
        hasher.update(":");
        hasher.update(realm);
        hasher.update(":");
        hasher.update(password);
        hasher.finalize()
    }

    fn calculate_ha1<T: Digest>(&self, hashed_user_realm_pass: &[u8]) -> String {
        if self.session {
            let qop_data = self.qop_data.as_ref().unwrap();
            let mut hasher = T::new();
            hasher.update(hashed_user_realm_pass);
            hasher.update(":");
            hasher.update(self.nonce());
            hasher.update(":");
            hasher.update(&qop_data.cnonce);
            hex::encode(hasher.finalize())
        } else {
            hex::encode(hashed_user_realm_pass)
        }
    }

    fn calculate_ha2<T: Digest>(&self, method: &str, uri: &str, body: Option<&[u8]>) -> String {
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
        hashed_user_realm_pass: &[u8],
        method: &str,
        uri: &str,
        body: Option<&[u8]>,
    ) -> String {
        let ha1 = self.calculate_ha1::<T>(hashed_user_realm_pass);

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

#[cfg(feature = "from-headers")]
impl<'a> TryFrom<&'a HeaderMap> for DigestAccess {
    type Error = DigestParseError;
    /// Returns a DigestScheme object if the HTTP response HeaderMap contains a digest authenticate header
    fn try_from(headers: &HeaderMap) -> Result<DigestAccess, Self::Error> {
        let mut err = DigestParseError::MissingDigest;
        let auth_headers = headers.get_all(WWW_AUTHENTICATE);
        for a in auth_headers.iter() {
            if a.len() > Self::MIN_AUTH_LENGTH {
                if let Ok(b) = a.to_str() {
                    return DigestAccess::create_from_www_auth(b);
                }
            } else {
                err = DigestParseError::Length;
            }
        }
        Err(err)
    }
}

#[cfg(feature = "from-headers")]
impl TryFrom<HeaderMap> for DigestAccess {
    type Error = DigestParseError;

    fn try_from(headers: HeaderMap) -> Result<Self, Self::Error> {
        DigestAccess::try_from(&headers)
    }
}
