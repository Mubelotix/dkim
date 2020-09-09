use std::convert::TryFrom;

use crate::dkim::PublicKey;
use crate::dkim::{
    CanonicalizationType,
    SigningAlgorithm,
    Header
};
use crate::hash::*;
use crate::canonicalization::*;
use crate::parsing::parse_mail;

#[derive(Debug)]
pub enum VerificationError {
    BodyHashesDontMatch,
    InvalidSpecifiedLenght,
    MissingDkimHeader,
    InvalidDkimHeader,
    VerificationFailed(rsa::errors::Error)
}

impl From<rsa::errors::Error> for VerificationError {
    fn from(e: rsa::errors::Error) -> Self {
        VerificationError::VerificationFailed(e)
    }
}

pub type MAIL<'a> = (&'a [(&'a str, &'a str)], &'a str);

pub fn verify_raw(raw_mail: &str) -> Result<Result<(), VerificationError>, ()> {
    let (headers, body) = parse_mail(raw_mail)?;

    Ok(verify((&headers, body)))
}

pub fn verify((headers, body): MAIL) -> Result<(), VerificationError> {
    let (name, value) = match &headers.iter().find::<_>(|e| unicase::eq_ascii(e.0, "DKIM-Signature")) {
        Some(dkim_header) => dkim_header,
        None => return Err(VerificationError::MissingDkimHeader),
    };
    let signature = Header::parse(name, value).map_err(|_| VerificationError::InvalidDkimHeader)?;

    let records = PublicKey::load(&signature.selector, &signature.sdid).unwrap();
    let public_key = records
        .iter()
        .filter_map(|r| PublicKey::try_from(r.as_str()).ok())
        .nth(0)
        .unwrap();

    verify_with_public_key_and_signature((headers, body), &public_key, &signature)
}

pub fn verify_with_public_key((headers, body): MAIL, public_key: &PublicKey) -> Result<(), VerificationError> {
    let (name, value) = match &headers.iter().find::<_>(|e| unicase::eq_ascii(e.0, "DKIM-Signature")) {
        Some(dkim_header) => dkim_header,
        None => return Err(VerificationError::MissingDkimHeader),
    };
    let signature = Header::parse(name, value).map_err(|_| VerificationError::InvalidDkimHeader)?;

    verify_with_public_key_and_signature((headers, body), public_key, &signature)
}

pub fn verify_with_public_key_and_signature((headers, body): MAIL, public_key: &PublicKey, signature: &Header) -> Result<(), VerificationError> {
    use rsa::{PublicKey, RSAPublicKey};

    // canonicalization
    let owned_body;
    let mut body = match signature.canonicalization.0 {
        CanonicalizationType::Relaxed => {
            owned_body = canonicalize_body_relaxed(
                body.to_string()
            );
            &owned_body
        },
        CanonicalizationType::Simple => {
            canonicalize_body_simple(body)
        }
    };
    let headers = match signature.canonicalization.0 {
        CanonicalizationType::Relaxed => {
            canonicalize_headers_relaxed(&headers, &signature.signed_headers)
        }
        CanonicalizationType::Simple => {
            canonicalize_headers_simple(&headers, &signature.signed_headers)
        }
    };
    if let Some(lenght) = signature.body_lenght {
        if body.get(lenght..).is_some() {
            body = body.get(lenght..).unwrap()
        } else {
            return Err(VerificationError::InvalidSpecifiedLenght);
        }
    }

    // hashing
    let body_hash = match signature.algorithm {
        SigningAlgorithm::RsaSha1 => body_hash_sha1(&body),
        SigningAlgorithm::RsaSha256 => body_hash_sha256(&body),
    };
    if body_hash != signature.body_hash {
        return Err(VerificationError::BodyHashesDontMatch);
    }
    let data_hash = match signature.algorithm {
        SigningAlgorithm::RsaSha1 => {
            data_hash_sha1(&headers, signature.original.as_ref().unwrap())
        }
        SigningAlgorithm::RsaSha256 => {
            data_hash_sha256(&headers, signature.original.as_ref().unwrap())
        }
    };

    // verifying
    let public_key = RSAPublicKey::from_pkcs8(&public_key.key_data).unwrap();
    public_key.verify(
        rsa::PaddingScheme::PKCS1v15Sign {
            hash: Some(match signature.algorithm {
                SigningAlgorithm::RsaSha1 => rsa::hash::Hash::SHA1,
                SigningAlgorithm::RsaSha256 => rsa::hash::Hash::SHA2_256,
            }),
        },
        &data_hash,
        &signature.signature,
    )?;

    Ok(())
}