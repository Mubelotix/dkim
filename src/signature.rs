use crate::prelude::*;
use crate::parsing::{
    quoted_printable::into_dqp, signature_header::tag_list_with_reassembled, ParsingError,
};

/// A struct reprensenting a DKIM-Signature header.  
/// It can be build using the builder syntax.
#[derive(Debug)]
pub struct Signature<'a> {
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

// builder
impl<'a> Signature<'a> {
    /// Initialize a new DKIM-Signature header with default fields. The first argument must be the signing domain (ex: "example.com") and the second argument must be the selector (ex: "dkim"). Making a txt lookup to "{selector}._domainkey.{sdid}" must return a DKIM record.
    ///   
    /// Uses relaxed canonicalization algorithms, Sha256 hash algorithm and signed headers will be `["mime-version", "references", "in-reply-to", "from", "date", "message-id", "subject", "to"]`. Optionnal fields are unset.  
    ///   
    /// The signature and body_hash fields can't be set manually (the `sign` method on an `Email` will do it).
    pub fn new(sdid: &'a str, selector: &'a str) -> Signature<'a> {
        Signature {
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

    pub fn with_algorithm(self, algorithm: SigningAlgorithm) -> Signature<'a> {
        Signature { algorithm, ..self }
    }

    pub fn with_canonicalization(
        self,
        canonicalization: (CanonicalizationType, CanonicalizationType),
    ) -> Signature<'a> {
        Signature {
            canonicalization,
            ..self
        }
    }

    pub fn with_signed_headers(self, signed_headers: Vec<&'a str>) -> Signature<'a> {
        Signature {
            signed_headers,
            ..self
        }
    }

    /// Unstable
    pub fn with_copied_headers(self, copied_headers: Vec<String>) -> Signature<'a> {
        Signature {
            copied_headers: Some(copied_headers),
            ..self
        }
    }

    pub fn with_auid(self, auid: String) -> Signature<'a> {
        Signature {
            auid: Some(auid),
            ..self
        }
    }

    pub fn with_body_lenght(self, body_lenght: usize) -> Signature<'a> {
        Signature {
            body_lenght: Some(body_lenght),
            ..self
        }
    }

    pub fn with_signature_timestamp(self, signature_timestamp: u64) -> Signature<'a> {
        Signature {
            signature_timestamp: Some(signature_timestamp),
            ..self
        }
    }

    pub fn with_signature_expiration(self, signature_expiration: u64) -> Signature<'a> {
        Signature {
            signature_expiration: Some(signature_expiration),
            ..self
        }
    }
}

// parser
impl<'a> Signature<'a> {
    pub fn parse(
        header_name: &str,
        header_value: &'a str,
    ) -> Result<Signature<'a>, ParsingError<'a>> {
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

        let (tags, reassembled) = tag_list_with_reassembled(&header_value)?;
        let reassembled = reassembled.ok_or_else(|| ParsingError::MissingTag("b"))?;

        for tag in tags {
            #[inline(always)]
            fn replace<'a, T>(
                to: &mut Option<T>,
                from: T,
                name: &'static str,
            ) -> Result<(), ParsingError<'a>> {
                if to.replace(from).is_some() {
                    Err(ParsingError::DuplicatedField(name))
                } else {
                    Ok(())
                }
            }

            match tag {
                Tag::AUID(id) => replace(&mut auid, id, "i")?,
                Tag::BodyHash(bh) => replace(&mut body_hash, bh, "bh")?,
                Tag::BodyLenght(l) => replace(&mut body_lenght, l, "l")?,
                Tag::Canonicalization(t, t2) => replace(&mut canonicalization, (t, t2), "c")?,
                Tag::CopiedHeaders(z) => replace(&mut copied_headers, z, "z")?,
                Tag::QueryMethods(q) if q == "dns/txt" => replace(&mut query_methods, q, "q")?,
                Tag::QueryMethods(_q) => {
                    return Err(ParsingError::UnableToAccomodateParameter("q", "This program does not support other options than \"dns/txt\" to retrieve the public key."))
                }
                Tag::SDID(d) => replace(&mut sdid, d, "d")?,
                Tag::Selector(s) => replace(&mut selector, s, "s")?,
                Tag::Signature(b) => replace(&mut signature, b, "b")?,
                Tag::SignatureExpiration(x) => replace(&mut signature_expiration, x, "x")?,
                Tag::SignatureTimestamp(t) => replace(&mut signature_timestamp, t, "t")?,
                Tag::SignedHeaders(h) => replace(&mut signed_headers, h, "h")?,
                Tag::SigningAlgorithm(a) => replace(&mut algorithm, a, "a")?,
                Tag::Version(n) if n == "1" => {
                    if got_v == true {
                        return Err(ParsingError::DuplicatedField("v"));
                    } else {
                        got_v = true;
                    }
                }
                Tag::Version(n) => return Err(ParsingError::UnsupportedVersion(n)),
                Tag::Unknown(_n, _v) => (),
            }
        }

        if !got_v {
            return Err(ParsingError::MissingTag("v"));
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
                reassembled_canonicalized =
                    format!("{}:{}{}", header_name, reassembled.0, reassembled.1)
            }
        }

        Ok(Signature {
            algorithm: algorithm.ok_or_else(|| ParsingError::MissingTag("a"))?,
            signature: signature.ok_or_else(|| ParsingError::MissingTag("b"))?,
            body_hash: body_hash.ok_or_else(|| ParsingError::MissingTag("bh"))?,
            canonicalization,
            sdid: sdid.ok_or_else(|| ParsingError::MissingTag("d"))?,
            selector: selector.ok_or_else(|| ParsingError::MissingTag("s"))?,
            signed_headers: signed_headers
                .ok_or_else(|| ParsingError::MissingTag("h"))?,
            query_method: query_methods.unwrap_or("dns/txt"),
            copied_headers,
            auid,
            body_lenght,
            signature_timestamp,
            signature_expiration,
            original: Some(reassembled_canonicalized),
        })
    }
}

impl<'a> std::string::ToString for Signature<'a> {
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
