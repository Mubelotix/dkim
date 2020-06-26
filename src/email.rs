use std::convert::TryFrom;
use email::{MimeMessage, UnfoldingStrategy};
use crate::{canonicalization::*, dkim::Header as DkimHeader, dkim::CanonicalizationType, hash::*};

#[derive(Debug)]
pub struct Email<'a> {
    raw: &'a str,
    parsed: MimeMessage,
    dkim_header: Option<DkimHeader>
}

#[derive(Debug)]
pub enum VerificationError {
    MissingDkimHeader,
    BodyHashesDontMatch,
    FailedSigning(rsa::errors::Error),
}

impl<'a> Email<'a> {
    pub fn verify(&self) -> Result<(), VerificationError> {
        let header = match &self.dkim_header {
            Some(dkim_header) => dkim_header,
            None => return Err(VerificationError::MissingDkimHeader),
        };

        let body = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => canonicalize_body_relaxed(string_tools::get_all_after(self.raw, "\r\n\r\n").to_string()),
            CanonicalizationType::Simple => canonicalize_body_simple(self.raw).to_string(),
        };
        
        let body_hash = body_hash_sha256(&body);

        if body_hash != header.body_hash {
            return Err(VerificationError::BodyHashesDontMatch);
        }

        let headers = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => canonicalize_headers_relaxed(self.raw, &header.signed_headers),
            CanonicalizationType::Simple => canonicalize_headers_simple(self.raw, &header.signed_headers),
        };

        let data_hash = data_hash_sha256(&headers, &header.original.as_ref().unwrap());

        let dns_record = crate::dkim::PublicKey::load(&header.selector, &header.sdid).unwrap();
        
        crate::verifier::verify(&data_hash, &header.signature, &dns_record.key.unwrap());

        Ok(())
    }

    pub fn sign(&mut self, mut header: DkimHeader, private_key: rsa::RSAPrivateKey) -> Result<String, VerificationError> {
        let body = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => canonicalize_body_relaxed(string_tools::get_all_after(self.raw, "\r\n\r\n").to_string()),
            CanonicalizationType::Simple => canonicalize_body_simple(self.raw).to_string(),
        };

        let body_hash = body_hash_sha256(&body);
        header.body_hash = body_hash;

        let headers = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => canonicalize_headers_relaxed(self.raw, &header.signed_headers),
            CanonicalizationType::Simple => canonicalize_headers_simple(self.raw, &header.signed_headers),
        };
        let data_hash = data_hash_sha256(&headers, &header.to_string());

        // TODO SHA1
        let signature = match private_key.sign(rsa::PaddingScheme::PKCS1v15Sign{hash: Some(rsa::hash::Hash::SHA2_256)}, &data_hash) {
            Ok(signature) => signature,
            Err(error) => return Err(VerificationError::FailedSigning(error)),
        };
        header.signature = signature;

        let mut mail = self.raw.to_string();
        let header = header.to_string();
        let idx = mail.find("\r\n\r\n").map(|i| i + 4).unwrap_or_else(|| mail.len());
        mail.insert_str(idx, &header);
        mail.insert_str(idx + header.len(), "\r\n");

        Ok(mail)
    }
}

impl<'a> TryFrom<&'a str> for Email<'a> {
    type Error = email::results::ParsingError;

    fn try_from(email: &'a str) -> Result<Email, Self::Error> {
        let parsed = MimeMessage::parse_with_unfolding_strategy(email, UnfoldingStrategy::None)?;
        let mut dkim_header = None;
        if let Some(header) = parsed.headers.get("DKIM-Signature".to_string()) {
            if let Ok(value) = header.get_value::<String>() {
                match DkimHeader::try_from(value.as_str()) {
                    Ok(header) => dkim_header = Some(header),
                    Err(e) => println!("c {:?}", e),
                }
            } else {
                println!("d")
            }
        } else {
            println!("a")
        }
        Ok(Email {
            raw: email,
            dkim_header,
            parsed,
        })
    }
}

impl<'a> Into<MimeMessage> for Email<'a> {
    fn into(self) -> MimeMessage {
        self.parsed
    }
}