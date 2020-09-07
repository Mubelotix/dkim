use std::convert::TryFrom;
use string_tools::get_all_after;
use string_tools::get_all_before_strict;
use crate::parsing::header::{
    ParsingError,
    Tag,
    tag_list_with_reassembled
};
use crate::parsing::dkim_quoted_printable::to_dkim_quoted_printable;

/// A struct reprensenting a DKIM-Signature header.  
/// It can be build using the builder syntax.
#[derive(Debug)]
pub struct Header<'a> {
    pub(crate) algorithm: SigningAlgorithm,
    pub(crate) signature: Vec<u8>,
    pub(crate) body_hash: Vec<u8>,
    pub(crate) query_method: &'a str,
    pub(crate) canonicalization: (CanonicalizationType, CanonicalizationType),
    pub(crate) sdid: &'a str,
    pub(crate) selector: &'a str,
    pub(crate) signed_headers: Vec<&'a str>,
    copied_headers: Option<Vec<String>>,
    auid: Option<String>,
    pub(crate) body_lenght: Option<usize>,
    signature_timestamp: Option<u64>,
    signature_expiration: Option<u64>,
    pub(crate) original: Option<(Option<&'a str>, &'a str, &'a str)>,
}

impl<'a> Header<'a> {
    /// Initialize a new DKIM-Signature header with default fields. The first argument must be the signing domain (ex: "example.com") and the second argument must be the selector (ex: "dkim"). Making a txt lookup to "{selector}._domainkey.{sdid}" must return a DKIM record.
    ///   
    /// Uses relaxed canonicalization algorithms, Sha256 hash algorithm and signed headers will be `["mime-version", "references", "in-reply-to", "from", "date", "message-id", "subject", "to"]`. Optionnal fields are unset.  
    ///   
    /// The signature and body_hash fields can't be set manually (the `sign` method on an `Email` will do it).
    pub fn new(sdid: &'a str, selector: &'a str) -> Header<'a> {
        Header {
            algorithm: SigningAlgorithm::RsaSha256,
            signature: Vec::new(),
            body_hash: Vec::new(),
            canonicalization: (CanonicalizationType::Relaxed, CanonicalizationType::Relaxed),
            sdid,
            selector,
            signed_headers: vec![
                "mime-version",
                "references",
                "in-reply-to",
                "from",
                "date",
                "message-id",
                "subject",
                "to",
            ],
            query_method: "dns/txt",
            copied_headers: None,
            auid: None,
            body_lenght: None,
            signature_timestamp: None,
            signature_expiration: None,
            original: None,
        }
    }

    pub fn parse(name: &'a str, value: &'a str) -> Result<Header<'a>, HeaderParsingError<'a>> {
        let mut auid = None;
        let mut body_hash = None;
        let mut body_lenght = None;
        let mut canonicalization = None;
        let mut copied_headers = None;
        let mut query_methods = None;
        let mut sdid = None;
        let mut selector = None;
        let mut signature = None;
        let mut signature_expiration = None;
        let mut signature_timestamp = None;
        let mut signed_headers = None;
        let mut algorithm = None;
        let mut got_v = false;

        let (tags, reassembled) = tag_list_with_reassembled(&value)?;
        let reassembled = reassembled.ok_or_else(|| HeaderParsingError::MissingField("b"))?;
        let reassembled = (Some(name), reassembled.0, reassembled.1);

        for tag in tags {
            match tag {
                Tag::AUID(id) => auid = Some(id),
                Tag::BodyHash(d) => body_hash = Some(d),
                Tag::BodyLenght(n) => body_lenght = Some(n),
                Tag::Canonicalization(t, t2) => canonicalization = Some((t, t2)),
                Tag::CopiedHeaders(h) => copied_headers = Some(h),
                Tag::QueryMethods(q) if q == "dns/txt" => query_methods = Some(q),
                Tag::QueryMethods(q) => return Err(HeaderParsingError::UnsupportedPublicKeyQueryMethods(q)),
                Tag::SDID(id) => sdid = Some(id),
                Tag::Selector(s) => selector = Some(s),
                Tag::Signature(d) => signature = Some(d),
                Tag::SignatureExpiration(t) => signature_expiration = Some(t),
                Tag::SignatureTimestamp(t) => signature_timestamp = Some(t),
                Tag::SignedHeaders(h) => signed_headers = Some(h),
                Tag::SigningAlgorithm(a) => algorithm = Some(a),
                Tag::Version(n) if n == 1 => got_v = true,
                Tag::Version(n) => return Err(HeaderParsingError::UnsupportedDkimVersion(n)),
                Tag::Unknown(_n, _v) => (),
            }
        }

        if !got_v {
            return Err(HeaderParsingError::MissingField("v"));
        }

        Ok(Header {
            algorithm: algorithm.ok_or_else(|| HeaderParsingError::MissingField("a"))?,
            signature: signature.ok_or_else(|| HeaderParsingError::MissingField("b"))?,
            body_hash: body_hash.ok_or_else(|| HeaderParsingError::MissingField("bh"))?,
            canonicalization: canonicalization.unwrap_or((CanonicalizationType::Simple, CanonicalizationType::Simple)),
            sdid: sdid.ok_or_else(|| HeaderParsingError::MissingField("d"))?,
            selector: selector.ok_or_else(|| HeaderParsingError::MissingField("s"))?,
            signed_headers: signed_headers.ok_or_else(|| HeaderParsingError::MissingField("h"))?,
            query_method: query_methods.unwrap_or("dns/txt"),
            copied_headers,
            auid,
            body_lenght,
            signature_timestamp,
            signature_expiration,
            original: Some(reassembled),
        })
    }

    pub fn with_algorithm(self, algorithm: SigningAlgorithm) -> Header<'a> {
        Header { algorithm, ..self }
    }

    pub fn with_canonicalization(
        self,
        canonicalization: (CanonicalizationType, CanonicalizationType),
    ) -> Header<'a> {
        Header {
            canonicalization,
            ..self
        }
    }

    pub fn with_signed_headers(self, signed_headers: Vec<&'a str>) -> Header<'a> {
        Header {
            signed_headers,
            ..self
        }
    }

    /// Unstable
    pub fn with_copied_headers(self, copied_headers: Vec<String>) -> Header<'a> {
        Header {
            copied_headers: Some(copied_headers),
            ..self
        }
    }

    pub fn with_auid(self, auid: String) -> Header<'a> {
        Header {
            auid: Some(auid),
            ..self
        }
    }

    pub fn with_body_lenght(self, body_lenght: usize) -> Header<'a> {
        Header {
            body_lenght: Some(body_lenght),
            ..self
        }
    }

    pub fn with_signature_timestamp(self, signature_timestamp: u64) -> Header<'a> {
        Header {
            signature_timestamp: Some(signature_timestamp),
            ..self
        }
    }

    pub fn with_signature_expiration(self, signature_expiration: u64) -> Header<'a> {
        Header {
            signature_expiration: Some(signature_expiration),
            ..self
        }
    }
}

impl<'a> std::string::ToString for Header<'a> {
    fn to_string(&self) -> String {
        let mut result = String::new();
        result.push_str(match self.algorithm {
            SigningAlgorithm::RsaSha1 => "v=1; a=rsa-sha1; b=",
            SigningAlgorithm::RsaSha256 => "v=1; a=rsa-sha256; b=",
        });

        result.push_str(&base64::encode(&self.signature));

        result.push_str("; bh=");
        result.push_str(&base64::encode(&self.body_hash));

        match self.canonicalization {
            (CanonicalizationType::Simple, CanonicalizationType::Simple) => (), // default value
            (CanonicalizationType::Simple, CanonicalizationType::Relaxed) => {
                result.push_str("; c=simple/relaxed")
            }
            (CanonicalizationType::Relaxed, CanonicalizationType::Simple) => {
                result.push_str("; c=relaxed")
            }
            (CanonicalizationType::Relaxed, CanonicalizationType::Relaxed) => {
                result.push_str("; c=relaxed/relaxed")
            }
        };

        result.push_str("; d=");
        result.push_str(&self.sdid);

        result.push_str("; h=");
        for (idx, signed_header) in self.signed_headers.iter().enumerate() {
            if idx > 0 {
                result.push(':');
            }
            result.push_str(signed_header);
        }

        if let Some(i) = &self.auid {
            result.push_str("; i=");
            // TODO DKIM quoted printable
            result.push_str(i);
        }

        if let Some(l) = &self.body_lenght {
            result.push_str("; l=");
            result.push_str(&l.to_string());
        }

        // q is not needed

        result.push_str("; s=");
        result.push_str(&self.selector);

        if let Some(t) = &self.signature_timestamp {
            result.push_str("; t=");
            result.push_str(&t.to_string());
        }

        if let Some(x) = &self.signature_expiration {
            result.push_str("; x=");
            result.push_str(&x.to_string());
        }

        if let Some(z) = &self.copied_headers {
            result.push_str("; z=");
            let value = to_dkim_quoted_printable(&z.join("|"));
            result.push_str(&value);
        }

        match self.canonicalization.0 {
            CanonicalizationType::Relaxed => {
                result = crate::canonicalization::canonicalize_header_relaxed(result);
                result.insert_str(0, "dkim-signature:");
                result
            }
            CanonicalizationType::Simple => {
                result.insert_str(0, "DKIM-Signature: ");
                result
            }
        }
    }
}

/// A struct reprensenting a DKIM dns record. (contains the public key and a few optional fields)
#[derive(Debug)]
pub struct PublicKey {
    sha1_supported: bool,
    sha256_supported: bool,
    subdomains_disallowed: bool,
    testing_domain: bool,
    key_type: String,
    note: Option<String>,
    pub(crate) key: Option<Vec<u8>>,
}

/// The hashing algorithm used when signing or verifying.
/// Should be sha256 but may be sha1.
#[derive(Debug, PartialEq)]
pub enum SigningAlgorithm {
    RsaSha1,
    RsaSha256,
}

/// The DKIM canonicalization algorithm.
#[derive(Debug, PartialEq)]
pub enum CanonicalizationType {
    /// Disallows modifications expect header addition during mail transit
    Simple,
    /// Allows space duplication and header addition during mail transit
    Relaxed,
}

#[derive(Debug)]
pub enum HeaderParsingError<'a> {
    DuplicatedField(&'static str),
    MissingField(&'static str),
    NotADkimSignatureHeader,
    UnsupportedDkimVersion(u8),
    UnsupportedPublicKeyQueryMethods(&'a str),
    InvalidBodyLenght(std::num::ParseIntError),
    ParsingError(ParsingError)
}

impl<'a> std::convert::From<ParsingError> for HeaderParsingError<'a> {
    fn from(e: ParsingError) -> HeaderParsingError<'a> {
        HeaderParsingError::ParsingError(e)
    }
}

#[derive(Debug)]
pub enum PublicKeyParsingError {
    DuplicatedField(&'static str),
    UnsupportedDkimVersion(String),
    InvalidQuotedPrintableValue(quoted_printable::QuotedPrintableError),
    InvalidUtf8(std::string::FromUtf8Error),
    InvalidBase64Value(base64::DecodeError),
    WspRequiredAfterCRLF,
    ServiceIntendedFor(Vec<String>),
    MissingKey,
    MissingRecord,
}

impl TryFrom<&str> for PublicKey {
    type Error = PublicKeyParsingError;

    #[allow(clippy::many_single_char_names)]
    fn try_from(data: &str) -> Result<PublicKey, PublicKeyParsingError> {
        let mut v = false;
        let mut h = false;
        let mut k = false;
        let mut s = false;
        let mut t = false;
        let mut sha1_supported = true;
        let mut sha256_supported = true;
        let mut subdomains_disallowed = false;
        let mut testing_domain = false;
        let mut key_type = String::from("rsa");
        let mut note: Option<String> = None;
        let mut key: Option<Option<Vec<u8>>> = None;

        for p in data.split(';') {
            match get_all_before_strict(p, "=") {
                None => (),
                Some(name) => {
                    let value = get_all_after(&p, "=").trim();
                    match name.trim() {
                        "v" => {
                            if v {
                                return Err(PublicKeyParsingError::DuplicatedField("v"));
                            } else if value == "DKIMV1" {
                                v = true;
                            } else {
                                return Err(PublicKeyParsingError::UnsupportedDkimVersion(
                                    value.to_string(),
                                ));
                            }
                        }
                        "h" => {
                            if h {
                                return Err(PublicKeyParsingError::DuplicatedField("h"));
                            } else {
                                h = true;
                                sha1_supported = false;
                                sha256_supported = false;
                                for hash_alg in value.split(':') {
                                    if hash_alg == "sha1" {
                                        sha1_supported = true;
                                    } else if hash_alg == "sha256" {
                                        sha256_supported = true;
                                    }
                                }
                            }
                        }
                        "k" => {
                            if k {
                                return Err(PublicKeyParsingError::DuplicatedField("k"));
                            } else {
                                k = true;
                                key_type = value.to_string();
                            }
                        }
                        "n" => {
                            if note.is_some() {
                                return Err(PublicKeyParsingError::DuplicatedField("n"));
                            } else {
                                note = match quoted_printable::decode(
                                    value,
                                    quoted_printable::ParseMode::Robust,
                                ) {
                                    Ok(note) => match String::from_utf8(note) {
                                        Ok(value) => Some(value),
                                        Err(error) => {
                                            return Err(PublicKeyParsingError::InvalidUtf8(error))
                                        }
                                    },
                                    Err(error) => {
                                        return Err(
                                            PublicKeyParsingError::InvalidQuotedPrintableValue(
                                                error,
                                            ),
                                        )
                                    }
                                };
                            }
                        }
                        "p" => {
                            if key.is_some() {
                                return Err(PublicKeyParsingError::DuplicatedField("p"));
                            } else {
                                let key_value = if value.contains(' ')
                                    || value.contains('\t')
                                    || value.contains("\r\n")
                                {
                                    let mut value = value.to_string();
                                    value.retain(|c| match c {
                                        '0'..='9' | 'A'..='Z' | 'a'..='z' | '+' | '/' | '=' => true,
                                        _ => false,
                                    });
                                    base64::decode(value)
                                } else {
                                    base64::decode(value)
                                };

                                key = match key_value {
                                    Ok(value) => Some(Some(value)),
                                    Err(_error) if value.is_empty() => Some(None),
                                    Err(error) => {
                                        return Err(PublicKeyParsingError::InvalidBase64Value(
                                            error,
                                        ))
                                    }
                                }
                            }
                        }
                        "s" => {
                            if s {
                                return Err(PublicKeyParsingError::DuplicatedField("s"));
                            } else {
                                let mut services = Vec::new();
                                for service in value.split(':') {
                                    services.push(service);
                                }
                                if !services.contains(&"email") && !services.contains(&"*") {
                                    return Err(PublicKeyParsingError::ServiceIntendedFor(
                                        services.iter().map(|v| v.to_string()).collect(),
                                    ));
                                }
                                s = true;
                            }
                        }
                        "t" => {
                            if t {
                                return Err(PublicKeyParsingError::DuplicatedField("t"));
                            } else {
                                t = true;
                                for flag in value.split(':') {
                                    if flag == "y" {
                                        testing_domain = true;
                                    } else if flag == "s" {
                                        subdomains_disallowed = true;
                                    }
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
        }

        Ok(PublicKey {
            sha1_supported,
            sha256_supported,
            subdomains_disallowed,
            testing_domain,
            key_type,
            note,
            key: key.ok_or(PublicKeyParsingError::MissingKey)?,
        })
    }
}

impl PublicKey {
    /// Creates a new PublicKey with all fields specified.
    pub fn new(
        sha1_supported: bool,
        sha256_supported: bool,
        subdomains_disallowed: bool,
        testing_domain: bool,
        key_type: String,
        note: Option<String>,
        key: Option<Vec<u8>>,
    ) -> PublicKey {
        PublicKey {
            sha1_supported,
            sha256_supported,
            subdomains_disallowed,
            testing_domain,
            key_type,
            note,
            key,
        }
    }

    /// Loads a public key from the DNS.
    pub fn load(selector: &str, domain: &str) -> Result<PublicKey, PublicKeyParsingError> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::Resolver;

        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
        let txt_fields = resolver
            .txt_lookup(&format!("{}._domainkey.{}", selector, domain))
            .unwrap();

        let mut records = Vec::new();
        for packets in txt_fields.iter().map(|data| data.txt_data()) {
            let mut response = Vec::new();
            for packet in packets {
                response.extend_from_slice(&packet);
            }
            let response = String::from_utf8(response).unwrap();
            records.push(PublicKey::try_from(response.as_str()));
        }

        if records.is_empty() {
            Err(PublicKeyParsingError::MissingRecord)
        } else if records.iter().filter(|r| r.is_ok()).count() > 0 {
            for record in records {
                if let Ok(record) = record {
                    return Ok(record);
                }
            }
            unreachable!();
        } else {
            Err(records.remove(0).unwrap_err())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dkim_header() {
        let header = Header::parse("Dkim-Signature", " v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap();

        println!("{:?}", header);
        println!("{:?}", header.to_string());
        println!("{:?}", header.original.unwrap());
    }

    #[test]
    fn get_dkim_record() {
        println!("{:?}", PublicKey::load("20161025", "gmail.com").unwrap());
    }
}
