use std::convert::TryFrom;
use email::{MimeMessage, UnfoldingStrategy};
use crate::{canonicalization::*, dkim::Header as DkimHeader, dkim::{CanonicalizationType, PublicKey}, hash::*};

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

        let public_key = PublicKey::load(&header.selector, &header.sdid).unwrap();
        self.verify_with_public_key(&public_key)
    }

    pub fn verify_with_public_key(&self, public_key: &PublicKey) -> Result<(), VerificationError> {
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

        crate::verifier::verify(&data_hash, &header.signature, &public_key.key.as_ref().unwrap());

        Ok(())
    }

    pub fn sign(&mut self, mut header: DkimHeader, private_key: &rsa::RSAPrivateKey) -> Result<String, VerificationError> {
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
        let idx = mail.find("\r\n\r\n").map(|i| i + 2).unwrap_or_else(|| mail.len());
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

#[test]
fn test_signing() {
    let mail = include_str!("/home/mubelotix/projects/mail/dkim/mail.txt");
    let mut mail = Email::try_from(mail).unwrap();

    let key = base64::decode("MIIEowIBAAKCAQEAgxoGICfYbPE2Z75oNqCxt559UcIOBuh6RmvIrAWSIgGfFHGFiksNS/uRNOM+JAHh7UbHZtCdT5nYpNuIFboOH8TxGVw58D3dFoi97llInbHpuxcQMmVErHiEZ/5rWtCKjBE851EFU4G/1YwR+PsO7/lB5+VnU3yb0s4YcbalsY+5IKIO/ocVXBaWqu471hGAPs4GyziuZ/I40xd5N2qi5Ws9uWOnJ/NFeuKCK+l7jOY0catqheft95CIVPR0d5ihuM1bRjS/mOKhDlj/ru8emmaCzeqToUshl8LT4HZ3YVhFiM1NEj7OYDcQibIFd61ENNHc21+TOwLq3pvSZN96vwIDAQABAoIBAQCAzyXrnBqZ11m0DrGH0tUp6w+IL9jmUq4o2Ke+1G5i+SLazDr/yIPU/uQJiag5apwXLG6ohxm45xijyYpohnhwIGkemK3YbH/4Lvwl3hVp0y8pghyI11Tk/DhjkObbwIAP5LPpNoK8LIRWBZx2+/0OLOHjPVMLBSh4s8PynhkoXfT1ej3PGh29SWr0fntxwR1O3dwxq5zD9xUL4h7ngT796YOr7C26z4rS9znwvR0jdA7bIrRHF/XKHFq6dLgu7USzfP+64YKPqfv/Kw1NmA04li5+2Yu3CPL+Qf7Wqi5AvxzlQ45IcVdQeD9FizUcfREKQXTE6QSQLomWspy6H/W5AoGBAOIMCbPcUiiDgigob/8z2DkWiRggyY9yOxZHl05KDe10GOdSs567wacB1RVonZf2iwmTyBQRePrWiamzF0HCrPhF5vOx9RgNiz6PdDr6+i5w8uIXcNbieqG6tI0hlkXUZcOhu3778lLwOyw4hcdqsZK30UAmPriXRn50skgnxtwTAoGBAJR5QFtBaI3sn+2waSx8xTPuS3bR37cespYwxzr6h3McfGPnpfrOTSX3kDbVHoztL1N4TGb1c8TMvb67X9ls81AKP6J0tFPxPp4PJeuicDrJlnVqzDcTYAvfDjtzs/PBoszBfECkq6NHXq1ozG7fp8ekxf+Fug5i+7Su6fWw9SQlAoGAMcOsrygl/j1VfjnIzko/o/HOJL2zIh1n3LPOH7I19rzEbsjKOnvjWj0RCDGL4FSqr2UVezWNiMuKaw2+ZP/SzKW2/peC+dShfxhd4k42ndrH3faDJQufK9PKw/dM+fqUnMkSWhZldtTkcgvPh+N5TG+jZZgF3uWO43AVf8UiBnkCgYBLjeBID+Lqxg0kYW9D6kJYCN1yG57iisaKU0wvISooU8ig9lKqbK0psu86V/1x7Yj1yvPmOOWushmko6lE9YJjqrNzMjxJsywQNtkvLbw6zja4jZ5aMIvhvqJ5comSc2krFRLrumB1eG4fhILzsPCqUZlITH6/r3MzIQeBtYkp2QKBgDkgpa0c+ep3020iOIjFzE9in2reyAj5Kvwh1li8TGrndh3pj4OL7+Qp4Dl0ndetcB+PoMN627haxbMkQMU3+yfBJH/lLWzP/o8DFuqlCC1YniUpof0G0gJsMZR/+v4FjBnrB4guXbmC7emQ/EZ9mybnc+ilN9vn6okAZ9zsGxTk").unwrap();
    let key = rsa::RSAPrivateKey::from_pkcs1(&key).unwrap();

    let mail = mail.sign(DkimHeader::new("mubelotix.dev".to_string(), "common".to_string()), &key).unwrap();
    let mail = Email::try_from(mail.as_str()).unwrap();

    let key = base64::decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgxoGICfYbPE2Z75oNqCxt559UcIOBuh6RmvIrAWSIgGfFHGFiksNS/uRNOM+JAHh7UbHZtCdT5nYpNuIFboOH8TxGVw58D3dFoi97llInbHpuxcQMmVErHiEZ/5rWtCKjBE851EFU4G/1YwR+PsO7/lB5+VnU3yb0s4YcbalsY+5IKIO/ocVXBaWqu471hGAPs4GyziuZ/I40xd5N2qi5Ws9uWOnJ/NFeuKCK+l7jOY0catqheft95CIVPR0d5ihuM1bRjS/mOKhDlj/ru8emmaCzeqToUshl8LT4HZ3YVhFiM1NEj7OYDcQibIFd61ENNHc21+TOwLq3pvSZN96vwIDAQAB").unwrap();
    mail.verify_with_public_key(&PublicKey::new(false, true, false, false, String::from("rsa"), None, Some(key))).unwrap();
}