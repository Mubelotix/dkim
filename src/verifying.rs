use crate::canonicalization::*;
use crate::hash::*;
use crate::parsing::parse_mail;
use crate::prelude::*;
use std::convert::TryFrom;

#[derive(Debug)]
pub enum VerificationError {
    BodyHashesDontMatch,
    InvalidSpecifiedLenght,
    MissingDkimHeader,
    InvalidDkimHeader,
    VerificationFailed(rsa::errors::Error),
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
    let (name, value) = match &headers
        .iter()
        .find::<_>(|e| unicase::eq_ascii(e.0, "DKIM-Signature"))
    {
        Some(dkim_header) => dkim_header,
        None => return Err(VerificationError::MissingDkimHeader),
    };
    let signature =
        Signature::parse(name, value).map_err(|_| VerificationError::InvalidDkimHeader)?;

    let records = PublicKey::load(&signature.selector, &signature.sdid).unwrap();
    let public_key = records
        .iter()
        .filter_map(|r| PublicKey::try_from(r.as_str()).ok())
        .nth(0)
        .unwrap();

    verify_with_public_key_and_signature((headers, body), &public_key, &signature)
}

pub fn verify_raw_with_public_key(
    raw_mail: &str,
    public_key: &PublicKey,
) -> Result<Result<(), VerificationError>, ()> {
    let (headers, body) = parse_mail(raw_mail)?;

    Ok(verify_with_public_key((&headers, body), public_key))
}

pub fn verify_with_public_key(
    (headers, body): MAIL,
    public_key: &PublicKey,
) -> Result<(), VerificationError> {
    let (name, value) = match &headers
        .iter()
        .find::<_>(|e| unicase::eq_ascii(e.0, "DKIM-Signature"))
    {
        Some(dkim_header) => dkim_header,
        None => return Err(VerificationError::MissingDkimHeader),
    };
    let signature =
        Signature::parse(name, value).map_err(|_| VerificationError::InvalidDkimHeader)?;

    verify_with_public_key_and_signature((headers, body), public_key, &signature)
}

pub fn verify_with_public_key_and_signature(
    (headers, body): MAIL,
    public_key: &PublicKey,
    signature: &Signature,
) -> Result<(), VerificationError> {
    use rsa::{PublicKey, RSAPublicKey};

    // canonicalization
    let owned_body;
    let mut body = match signature.canonicalization.0 {
        CanonicalizationType::Relaxed => {
            owned_body = canonicalize_body_relaxed(body.to_string());
            &owned_body
        }
        CanonicalizationType::Simple => canonicalize_body_simple(body),
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
        SigningAlgorithm::RsaSha1 => data_hash_sha1(&headers, signature.original.as_ref().unwrap()),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify() {
        verify_raw("Received: by mail-oi1-f177.google.com with SMTP id e4so8660662oib.1\r\n        for <mubelotix@mubelotix.dev>; Tue, 30 Jun 2020 01:43:28 -0700 (PDT)\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=gmail.com; s=20161025;\r\n        h=mime-version:from:date:message-id:subject:to;\r\n        bh=5NNwu8gdOD3ZoZD58FM4gy7PeYn+BudAJmLL+5Moe58=;\r\n        b=aTCNiDUsK2fSxrWf9zWJo03xIpgkFIaV6v/OpcIgEtysxN26K/UR6BofP2KL24DSZl\r\n         FfQLpoWmD0GyU9sN294CUtcYW9xZR5LkQCicxFos/qHOYIaYn/BTwApvyAwdio1OYMM4\r\n         EYJybljPidGHVRaVcLqKfjy0U7HdjHMzm4rTIsvzn7nVm1ziWaZKS0O8QSAMXyXVTkPH\r\n         cIIHa2e1fc76ZLCFLtcI+e/SszpBwVqnvNgWYWBYiGFvjC4CCGJouGxb9z58rzA03XhW\r\n         Ix0uR2YeRYxugTVP/tAf5mo34KWjwKr98IbmYs8nDrZZSliCiyV8B7bWHXM3qXyepXnl\r\n         CQOA==\r\nX-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=1e100.net; s=20161025;\r\n        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;\r\n        bh=5NNwu8gdOD3ZoZD58FM4gy7PeYn+BudAJmLL+5Moe58=;\r\n        b=SEIL6qJEGH/+sVou4i84kC4vEEsLShYrmKLAlM/7V1fIIbpyQWDRpehMKnlGFKmTCx\r\n         Mz1NijW6tbjDJ+1eF3aE/MNSzhim2eO4JmcK5kZ4vlZzzPWE+GacZqc3QNtAufgA/EqP\r\n         eWTuFSPtSY2vHJdRX21vq8WpP31KdG0JKcv3ZykDqH0y1dAM1sAGR3Gmrcyu+HGA9Ug5\r\n         BrYx1ZPyjYOtlXEiGqaKRsrBlB5P42n2aU0TwZYrEVi9N5TULM4bS+bLtP3FmxP7uIP2\r\n         ZKuFKbcTTveG3+DaaOE7HK/dHXWXZZC9RaS/yzGettgXiwmaAENcONpTwg1jD70DU5a9\r\n         DYHg==\r\nX-Gm-Message-State: AOAM533sOvLV7q5oj9SIWatwQ3kCiOgSZHBhJb0R93ImzSZav4QObpV2\r\n        pLSheyz34dtdedvMg8G3go4HsIP3ytqkN8f9j+ZTvFkx\r\nX-Google-Smtp-Source: ABdhPJzLJRsIQigY2u6fwn04UxksGTqbklM5igDK5fVI2kljDUPeTOPWxkM4IEUQpRb6Ciacz58Kj9Dqy61/LiiyDyA=\r\nX-Received: by 2002:aca:d681:: with SMTP id n123mr15403808oig.82.1593506599851;\r\n Tue, 30 Jun 2020 01:43:19 -0700 (PDT)\r\nMIME-Version: 1.0\r\nFrom: Mubelotix <mubelotix@gmail.com>\r\nDate: Tue, 30 Jun 2020 10:43:08 +0200\r\nMessage-ID: <CANc=2UXAvRBx-A7SP9JWm=pby29s_zdFvfMDUprZ+PN_8XuO+w@mail.gmail.com>\r\nSubject: Test email\r\nTo: mubelotix@mubelotix.dev\r\nContent-Type: multipart/alternative; boundary=\"000000000000d4d95805a9492a3c\"\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nTest body\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">Test body</div>\r\n\r\n--000000000000d4d95805a9492a3c--").unwrap().unwrap();
    }
}