use digest::{Digest, Output};
use md5::Md5;
use nom::{
    branch::alt,
    bytes::complete::{is_a, is_not, tag, tag_no_case, take_till, take_till1, take_while1},
    character::{
        complete::{char, multispace0, multispace1},
        is_newline,
        streaming::newline,
    },
    combinator::{opt, rest},
    error::ParseError,
    multi::{many_m_n, separated_list0},
    sequence::{delimited, preceded, terminated, tuple},
    Finish, IResult,
};
use rand::{
    distributions::{Distribution, Uniform},
    seq::SliceRandom,
    thread_rng,
};
use sha2::{Sha256, Sha512_256};
use std::fmt;
use std::str::FromStr;

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

#[derive(Debug)]
pub struct DigestAccess {
    nonce: String,
    domain: Vec<String>,
    realm: String,
    opaque: Option<String>,
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
        Self::create_from_www_auth(auth)
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
        if auth.len() < Self::MIN_AUTH_LENGTH {
            return Err(DigestParseError::Length);
        }
        let (input, _digest) =
            Self::digest_challenge(auth).map_err(|_| DigestParseError::MissingDigest)?;

        let (input, directives) = separated_list0(tag(","), Self::directive)(input)
            .map_err(|_| DigestParseError::MissingNonce)?;

        let mut realm = None;
        let mut nonce = None;
        let mut domain = Vec::new();
        let mut opaque = None;
        let mut stale = false;
        let mut alg_sess = (DigestAlgorithm::MD5, false);
        let mut userhash = false;
        let mut qop = QualityOfProtection::None;
        for (key, val) in directives {
            match key.to_ascii_lowercase().as_str() {
                "realm" => realm = Some(val.to_owned()),
                "nonce" => nonce = Some(val.to_owned()),
                "domain" => domain = val.split(' ').map(|v| v.to_owned()).collect(),
                "opaque" => opaque = Some(val.to_owned()),
                "stale" => stale = val.eq_ignore_ascii_case("true"),
                "algorithm" => alg_sess = Self::algorithm_and_session(val),
                "qop" => qop = Self::quality_of_protection(val),
                "userhash" => userhash = val.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }
        let algorithm = alg_sess.0;
        let session = alg_sess.1;

        match (nonce, realm) {
            (_, None) => Err(DigestParseError::MissingRealm),
            (None, _) => Err(DigestParseError::MissingNonce),
            (Some(nonce), Some(realm)) => Ok(Self {
                nonce,
                domain,
                realm,
                opaque,
                stale,
                nonce_count: 0,
                algorithm,
                session,
                userhash,
                qop,
                qop_data: None,
                username: None,
                hashed_user_realm_pass: None,
            }),
        }
    }

    #[inline(always)]
    fn digest_challenge(input: &str) -> IResult<&str, &str> {
        terminated(tag_no_case("digest"), multispace1)(input)
    }

    #[inline(always)]
    fn key(input: &str) -> IResult<&str, &str> {
        terminated(take_till1(|c: char| c == '='), char('='))(input)
    }

    #[inline(always)]
    fn val(input: &str) -> IResult<&str, &str> {
        alt((
            delimited(char('"'), is_not("\""), char('"')),
            terminated(is_not(",\r\n \t"), multispace0),
        ))(input)
    }

    #[inline(always)]
    fn directive(input: &str) -> IResult<&str, (&str, &str)> {
        // Directive consists of key (bare string) followed by =,
        let (input, (_discard, key, val)) = tuple((multispace0, Self::key, Self::val))(input)?;
        Ok((input, (key, val)))
    }

    fn algorithm_and_session(algorithm: &str) -> (DigestAlgorithm, bool) {
        let alg_str = algorithm.to_ascii_lowercase();
        if alg_str.contains("sha-256") {
            (DigestAlgorithm::SHA256, alg_str.contains("sha-256-sess"))
        } else if alg_str.contains("sha-512-256") {
            (
                DigestAlgorithm::SHA512_256,
                alg_str.contains("sha-512-256-sess"),
            )
        } else if alg_str.contains("md5-sess") {
            (DigestAlgorithm::MD5, true)
        } else {
            (DigestAlgorithm::MD5, false)
        }
    }

    fn quality_of_protection(qop: &str) -> QualityOfProtection {
        let qop_str = qop.to_ascii_lowercase();
        if qop_str.contains(QualityOfProtection::AuthInt.to_str()) {
            QualityOfProtection::AuthInt
        } else {
            QualityOfProtection::Auth
        }
    }

    fn realm(&self) -> &str {
        self.realm.as_str()
    }

    pub fn nonce(&self) -> &str {
        self.nonce.as_str()
    }

    fn opaque(&self) -> Option<&str> {
        self.opaque.as_ref().map(|o| o.as_str())
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
impl TryFrom<&HeaderMap> for DigestAccess {
    type Error = DigestParseError;
    /// Returns a DigestScheme object if the HTTP response HeaderMap contains a digest authenticate header
    fn try_from(headers: &HeaderMap) -> Result<DigestAccess, Self::Error> {
        let auth_headers = headers.get_all(WWW_AUTHENTICATE);
        let mut err = DigestParseError::Length;
        for a in auth_headers.iter() {
            if a.len() > Self::MIN_AUTH_LENGTH {
                if let Ok(b) = a.to_str() {
                    return DigestAccess::create_from_www_auth(b);
                } else {
                    err = DigestParseError::InvalidEncoding;
                }
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
