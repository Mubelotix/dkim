use std::convert::TryFrom;
use email::{MimeMessage, UnfoldingStrategy};
use crate::{canonicalization::*, dkim::DkimHeader, hash::*};

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
}

impl<'a> Email<'a> {
    pub fn verify(&self) -> Result<(), VerificationError> {
        let dkim_header = match &self.dkim_header {
            Some(dkim_header) => dkim_header,
            None => return Err(VerificationError::MissingDkimHeader),
        };

        let headers = if let Some(dkim_signature) = &self.dkim_header {
            canonicalize_headers_relaxed(self.raw, &dkim_signature.signed_headers)
        } else {
            canonicalize_headers_relaxed(self.raw, &Vec::new())
        };
        
        let body = canonicalize_body_relaxed(string_tools::get_all_after(self.raw, "\r\n\r\n").to_string());
        let body_hash = body_hash_sha256(&body);

        if body_hash != dkim_header.body_hash {
            return Err(VerificationError::BodyHashesDontMatch);
        }

        let data_hash = data_hash_sha256(&headers, &dkim_header.original.as_ref().unwrap());
        
        crate::verifier::verify(&data_hash, &dkim_header.signature);

        Ok(())
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