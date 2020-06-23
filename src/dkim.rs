use std::convert::TryFrom;
use string_tools::get_all_after;
use string_tools::get_all_before_strict;

#[derive(Debug)]
pub struct DkimHeader {
    algorithm: SigningAlgorithm,
    signature: Vec<u8>,
    body_hash: Vec<u8>,
    canonicalization: (CanonicalizationType, CanonicalizationType),
    sdid: String,
    selector: String,
    pub(crate) signed_headers: Vec<String>,
    copied_headers: Option<String>,
    auid: Option<String>,
    body_lenght: Option<usize>,
    signature_timestamp: Option<usize>,
    signature_expiration: Option<usize>,
}

#[derive(Debug)]
pub enum SigningAlgorithm {
    RsaSha1,
    RsaSha256,
}

#[derive(Debug)]
pub enum CanonicalizationType {
    Simple,
    Relaxed
}

#[derive(Debug)]
pub enum DkimParsingError {
    DuplicatedField(&'static str),
    MissingField(&'static str),
    UnsupportedDkimVersion(String),
    UnsupportedSigningAlgorithm(String),
    UnsupportedPublicKeyQueryMethods(String),
    InvalidBase64Value(base64::DecodeError),
    InvalidCanonicalizationType(String),
    InvalidBodyLenght(std::num::ParseIntError),
    InvalidSignatureTimestamp(std::num::ParseIntError),
    InvalidSignatureExpiration(std::num::ParseIntError),
}

impl TryFrom<String> for DkimHeader {
    type Error = DkimParsingError;

    fn try_from(mut value: String) -> Result<DkimHeader, Self::Error> {
        let mut got_v = false;
        let mut algorithm = None;
        let mut signature = None;
        let mut body_hash = None;
        let mut canonicalization = None;
        let mut sdid = None;
        let mut selector = None;
        let mut signed_headers = None;
        let mut copied_headers = None;
        let mut auid = None;
        let mut body_lenght = None;
        let mut signature_timestamp = None;
        let mut signature_expiration = None;
        let mut q = false;

        for e in value.split(';') {
            match get_all_before_strict(e, "=") {
                None => (),
                Some(name) => {
                    let value = get_all_after(&e, "=").trim();
                    match name.trim() {
                        "v" => {
                            if got_v {
                                return Err(DkimParsingError::DuplicatedField("v"))
                            } else if value != "1" {
                                return Err(DkimParsingError::UnsupportedDkimVersion(value.to_string()))
                            } else {
                                got_v = true;
                            }
                        },
                        "a" => {
                            if algorithm.is_some() {
                                return Err(DkimParsingError::DuplicatedField("a"))
                            } else if value == "rsa-sha1" {
                                algorithm = Some(SigningAlgorithm::RsaSha1)
                            } else if value == "rsa-sha256"{
                                algorithm = Some(SigningAlgorithm::RsaSha256)
                            } else {
                                return Err(DkimParsingError::UnsupportedSigningAlgorithm(value.to_string()))
                            }
                        },
                        "b" => {
                            if signature.is_some() {
                                return Err(DkimParsingError::DuplicatedField("b"))
                            } else {
                                let value = if value.contains(' ') || value.contains('\t') {
                                    let mut value = value.to_string();
                                    value.retain(|c| c.is_alphanumeric());
                                    base64::decode(value)
                                } else {
                                    base64::decode(value)
                                };
                                
                                signature = match value {
                                    Ok(value) => Some(value), // TODO check size
                                    Err(e) => return Err(DkimParsingError::InvalidBase64Value(e))
                                };
                            }
                        },
                        "bh" => {
                            if body_hash.is_some() {
                                return Err(DkimParsingError::DuplicatedField("bh"))
                            } else {
                                let value = if value.contains(' ') || value.contains('\t') {
                                    let mut value = value.to_string();
                                    value.retain(|c| c.is_alphanumeric());
                                    base64::decode(value)
                                } else {
                                    base64::decode(value)
                                };
                                
                                body_hash = match value {
                                    Ok(value) => Some(value), // TODO check size
                                    Err(e) => return Err(DkimParsingError::InvalidBase64Value(e))
                                };
                            }
                        },
                        "c" => {
                            if canonicalization.is_some() {
                                return Err(DkimParsingError::DuplicatedField("c"))
                            } else {
                                match value {
                                    "relaxed/relaxed" => canonicalization = Some((CanonicalizationType::Relaxed, CanonicalizationType::Relaxed)),
                                    "relaxed/simple" | "relaxed" => canonicalization = Some((CanonicalizationType::Relaxed, CanonicalizationType::Simple)),
                                    "simple/relaxed" => canonicalization = Some((CanonicalizationType::Simple, CanonicalizationType::Relaxed)),
                                    "simple/simple" | "simple" => canonicalization = Some((CanonicalizationType::Simple, CanonicalizationType::Simple)),
                                    value => return Err(DkimParsingError::InvalidCanonicalizationType(value.to_string()))
                                }
                            }
                        },
                        "d" => {
                            if sdid.is_some() {
                                return Err(DkimParsingError::DuplicatedField("d"))
                            } else {
                                sdid = Some(value.to_string());
                            }
                        },
                        "h" => {
                            if signed_headers.is_some() {
                                return Err(DkimParsingError::DuplicatedField("h"))
                            } else {
                                let mut headers = Vec::new();
                                for header in value.split(':') {
                                    headers.push(header.to_lowercase())
                                }
                                signed_headers = Some(headers);
                            }
                        },
                        "i" => {
                            if auid.is_some() {
                                return Err(DkimParsingError::DuplicatedField("i"))
                            } else {
                                auid = Some(value.to_string());
                            }
                        },
                        "l" => {
                            if body_lenght.is_some() {
                                return Err(DkimParsingError::DuplicatedField("l"))
                            } else {
                                body_lenght = match value.parse::<usize>() {
                                    Ok(value) => Some(value),
                                    Err(e) => return Err(DkimParsingError::InvalidBodyLenght(e))
                                };
                            }
                        },
                        "q" => {
                            if q {
                                return Err(DkimParsingError::DuplicatedField("q"))
                            } else {
                                let mut methods = Vec::new();
                                for method in value.split(':') {
                                    methods.push(method)
                                }
                                if !methods.contains(&"dns/txt") {
                                    return Err(DkimParsingError::UnsupportedPublicKeyQueryMethods(format!("{:?}", methods)))
                                }
                                q = true;
                            }
                        },
                        "s" => {
                            if selector.is_some() {
                                return Err(DkimParsingError::DuplicatedField("s"))
                            } else {
                                selector = Some(value.to_string());
                            }
                        },
                        "t" => {
                            if signature_timestamp.is_some() {
                                return Err(DkimParsingError::DuplicatedField("t"))
                            } else {
                                signature_timestamp = match value.parse::<usize>() {
                                    Ok(value) => Some(value),
                                    Err(e) => return Err(DkimParsingError::InvalidSignatureTimestamp(e))
                                };
                            }
                        },
                        "x" => {
                            if signature_expiration.is_some() {
                                return Err(DkimParsingError::DuplicatedField("x"))
                            } else {
                                signature_expiration = match value.parse::<usize>() {
                                    Ok(value) => Some(value),
                                    Err(e) => return Err(DkimParsingError::InvalidSignatureExpiration(e))
                                };
                            }
                        },
                        "z" => {
                            if copied_headers.is_some() {
                                return Err(DkimParsingError::DuplicatedField("z"))
                            } else {
                                copied_headers = Some(value.to_string());
                            }
                        },
                        _ => (),
                    }
                }
            }
        }
        Ok(DkimHeader {
            algorithm: algorithm.ok_or_else(|| DkimParsingError::MissingField("a"))?,
            signature: signature.ok_or_else(|| DkimParsingError::MissingField("b"))?,
            body_hash: body_hash.ok_or_else(|| DkimParsingError::MissingField("bh"))?,
            canonicalization: canonicalization.unwrap_or((CanonicalizationType::Simple, CanonicalizationType::Simple)),
            sdid: sdid.ok_or_else(|| DkimParsingError::MissingField("d"))?,
            selector: selector.ok_or_else(|| DkimParsingError::MissingField("s"))?,
            signed_headers: signed_headers.ok_or_else(|| DkimParsingError::MissingField("h"))?,
            copied_headers,
            auid,
            body_lenght,
            signature_timestamp,
            signature_expiration,
        })
    }
}

#[cfg(test)]
#[test]
fn parse_dkim_header() {
    let header = DkimHeader::try_from(" v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR".to_string()).unwrap();

    println!("{:?}", header);
}
