use std::convert::TryFrom;
use email::MimeMessage;
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
            println!("{:#?}", (base64::encode(body_hash), base64::encode(&dkim_header.body_hash)));
            return Err(VerificationError::BodyHashesDontMatch);
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for Email<'a> {
    type Error = email::results::ParsingError;

    fn try_from(email: &'a str) -> Result<Email, Self::Error> {
        let parsed = MimeMessage::parse(email)?;
        Ok(Email {
            raw: email,
            dkim_header: parsed.headers.get("DKIM-Signature".to_string()).map(|h| if let Ok(value) = h.get_value::<String>() {DkimHeader::try_from(value.as_str()).ok()} else {None}).flatten(),
            parsed,
        })
    }
}

impl<'a> Into<MimeMessage> for Email<'a> {
    fn into(self) -> MimeMessage {
        self.parsed
    }
}