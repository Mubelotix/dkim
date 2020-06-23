use std::convert::TryFrom;
use email::MimeMessage;
use crate::{canonicalization::*, dkim::DkimHeader};

#[derive(Debug)]
pub struct Email<'a> {
    raw: &'a str,
    parsed: MimeMessage,
    dkim_header: Option<DkimHeader>
}

impl<'a> Email<'a> {
    pub fn canonicalize_relaxed(&self) -> (String, String) {
        (if let Some(dkim_signature) = &self.dkim_header {
            canonicalize_headers_relaxed(self.raw, &dkim_signature.signed_headers)
        } else {
            canonicalize_headers_relaxed(self.raw, &Vec::new())
        }, canonicalize_body_relaxed(self.parsed.body.clone()))
    }
}

impl<'a> TryFrom<&'a str> for Email<'a> {
    type Error = email::results::ParsingError;

    fn try_from(email: &'a str) -> Result<Email, Self::Error> {
        let parsed = MimeMessage::parse(email)?;
        Ok(Email {
            raw: email,
            dkim_header: parsed.headers.get("DKIM-Signature".to_string()).map(|h| if let Ok(value) = h.get_value::<String>() {DkimHeader::try_from(value).ok()} else {None}).flatten(),
            parsed,
        })
    }
}

impl<'a> Into<MimeMessage> for Email<'a> {
    fn into(self) -> MimeMessage {
        self.parsed
    }
}