use crate::parsing::{
    ParsingError,
    quoted_printable::into_dqp,
    dns_record::dns_record_tag,
    tag_value_list::tag_list,
    signature_header::tag_list_with_reassembled,
};
use std::convert::TryFrom;

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
    pub(crate) original: Option<String>,
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
        use crate::parsing::signature_header::Tag;

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

        for tag in tags {
            match tag {
                Tag::AUID(id) => auid = Some(id),
                Tag::BodyHash(d) => body_hash = Some(d),
                Tag::BodyLenght(n) => body_lenght = Some(n),
                Tag::Canonicalization(t, t2) => canonicalization = Some((t, t2)),
                Tag::CopiedHeaders(h) => copied_headers = Some(h),
                Tag::QueryMethods(q) if q == "dns/txt" => query_methods = Some(q),
                Tag::QueryMethods(q) => {
                    return Err(HeaderParsingError::UnsupportedPublicKeyQueryMethods(q))
                }
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

        let canonicalization = canonicalization
            .unwrap_or((CanonicalizationType::Simple, CanonicalizationType::Simple));
        let reassembled_canonicalized;
        match &canonicalization.0 {
            CanonicalizationType::Relaxed => {
                reassembled_canonicalized = format!(
                    "dkim-signature:{}",
                    crate::canonicalization::canonicalize_header_relaxed(
                        reassembled.0.to_string() + reassembled.1
                    )
                )
            }
            CanonicalizationType::Simple => {
                reassembled_canonicalized = format!("{}:{}{}", name, reassembled.0, reassembled.1)
            }
        }

        Ok(Header {
            algorithm: algorithm.ok_or_else(|| HeaderParsingError::MissingField("a"))?,
            signature: signature.ok_or_else(|| HeaderParsingError::MissingField("b"))?,
            body_hash: body_hash.ok_or_else(|| HeaderParsingError::MissingField("bh"))?,
            canonicalization,
            sdid: sdid.ok_or_else(|| HeaderParsingError::MissingField("d"))?,
            selector: selector.ok_or_else(|| HeaderParsingError::MissingField("s"))?,
            signed_headers: signed_headers.ok_or_else(|| HeaderParsingError::MissingField("h"))?,
            query_method: query_methods.unwrap_or("dns/txt"),
            copied_headers,
            auid,
            body_lenght,
            signature_timestamp,
            signature_expiration,
            original: Some(reassembled_canonicalized),
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
            let value = into_dqp(&z.join("|"));
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
    ParsingError(ParsingError),
}

impl<'a> std::convert::From<ParsingError> for HeaderParsingError<'a> {
    fn from(e: ParsingError) -> HeaderParsingError<'a> {
        HeaderParsingError::ParsingError(e)
    }
}

#[derive(Debug)]
pub enum PublicKeyParsingError<'a> {
    MissingTag(&'static str),
    DuplicatedField(&'static str),
    UnsupportedDkimVersion(&'a str),
    UnexpectedService,

    InvalidQuotedPrintableValue(quoted_printable::QuotedPrintableError),
    InvalidUtf8(std::string::FromUtf8Error),
    InvalidBase64Value(base64::DecodeError),
    WspRequiredAfterCRLF,
    ServiceIntendedFor(Vec<String>),
    MissingKey,
    MissingRecord,
    ParsingError(ParsingError)
}

impl<'a> From<ParsingError> for PublicKeyParsingError<'a> {
    fn from(e: ParsingError) -> Self {
        PublicKeyParsingError::ParsingError(e)
    }
}

/// A struct reprensenting a DKIM dns record. (contains the public key and a few optional fields)
#[derive(Debug)]
pub struct PublicKey<'a> {
    pub(crate) acceptable_hash_algorithms: Option<Vec<&'a str>>,
    pub(crate) key_type: &'a str,
    pub(crate) key_data: Vec<u8>,
    pub(crate) service_types: Vec<&'a str>,
    pub(crate) flags: Vec<&'a str>,
    pub(crate) notes: Option<String>
}

impl<'a> TryFrom<&'a str> for PublicKey<'a> {
    type Error = PublicKeyParsingError<'a>;

    #[allow(clippy::many_single_char_names)]
    fn try_from(input: &'a str) -> Result<PublicKey, PublicKeyParsingError> {
        use crate::parsing::dns_record::Tag;

        let mut version: Option<&'a str> = None;
        let mut acceptable_hash_algorithms: Option<Vec<&'a str>> = None;
        let mut key_type: Option<&'a str> = None;
        let mut key_data: Option<Vec<u8>> = None;
        let mut service_types: Option<Vec<&'a str>> = None;
        let mut flags: Option<Vec<&'a str>> = None;
        let mut notes: Option<String> = None;

        for tag in tag_list(input, &dns_record_tag)? {
            #[inline(always)]
            fn replace<'a, T>(to: &mut Option<T>, from: T, name: &'static str) -> Result<(), PublicKeyParsingError<'a>> {
                if to.replace(from).is_some() {
                    Err(PublicKeyParsingError::DuplicatedField(name))
                } else {
                    Ok(())
                }
            }

            match tag {
                Tag::Version(v) => replace(&mut version, v, "v")?,
                Tag::AcceptableHashAlgorithms(algorithms) => replace(&mut acceptable_hash_algorithms, algorithms, "h")?,
                Tag::KeyType(k) => replace(&mut key_type, k, "k")?,
                Tag::Notes(n) => replace(&mut notes, n, "n")?,
                Tag::PublicKey(data) => replace(&mut key_data, data, "p")?,
                Tag::ServiceTypes(services) => replace(&mut service_types, services, "s")?,
                Tag::Flags(t) => replace(&mut flags, t, "f")?,
                Tag::Unknown(_n, _v) => (),
            }
        }

        if let Some(version) = version {
            if version != "DKIM1" {
                return Err(PublicKeyParsingError::UnsupportedDkimVersion(version));
            }
        }

        if let Some(service_types) = &service_types {
            if !service_types.contains(&"email") && !service_types.contains(&"*") {
                return Err(PublicKeyParsingError::UnexpectedService)
            }
        }

        Ok(PublicKey {
            acceptable_hash_algorithms,
            key_type: key_type.unwrap_or("rsa"),
            key_data: key_data.ok_or( PublicKeyParsingError::MissingTag("p"))?,
            service_types: service_types.unwrap_or(vec!["*"]),
            flags: flags.unwrap_or(Vec::new()),
            notes,
        })
    }
}

impl<'a> PublicKey<'a> {
    /// Creates a new PublicKey with all fields specified.
    pub fn new(
        acceptable_hash_algorithms: Option<Vec<&'a str>>,
        key_type: &'a str,
        key_data: Vec<u8>,
        service_types: Vec<&'a str>,
        flags: Vec<&'a str>,
        notes: Option<String>
    ) -> PublicKey<'a> {
        PublicKey {
            acceptable_hash_algorithms,
            key_type,
            key_data,
            service_types,
            flags,
            notes
        }
    }

    /// Loads a public key from the DNS.
    pub fn load(selector: &str, domain: &str) -> Result<Vec<String>, PublicKeyParsingError<'a>> {
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
                response.extend(packet.iter());
            }
            let response = String::from_utf8(response).unwrap();
            records.push(response);
        }

        if records.is_empty() {
            Err(PublicKeyParsingError::MissingRecord)
        } else {
            Ok(records)
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
