use crate::{
    canonicalization::*,
    dkim::Header as DkimHeader,
    dkim::{CanonicalizationType, PublicKey},
    hash::*,
};
use email_parser::parser::parse_message_with_separators;
use std::convert::TryFrom;

/// The mail struct used to sign or verify a mail.
#[derive(Debug)]
pub struct Email<'a> {
    raw: &'a str,
    pub(crate) parsed: (Vec<(&'a str, &'a str, &'a str)>, Option<&'a str>),
    dkim_header: Option<DkimHeader>,
}

#[derive(Debug)]
pub enum VerificationError {
    MissingDkimHeader,
    BodyHashesDontMatch,
    FailedSigning(rsa::errors::Error),
}

impl std::convert::From<rsa::errors::Error> for VerificationError {
    fn from(error: rsa::errors::Error) -> Self {
        VerificationError::FailedSigning(error)
    }
}

impl<'a> Email<'a> {
    /// Verify the mail after loading the public key from the DNS.
    pub fn verify(&self) -> Result<(), VerificationError> {
        let header = match &self.dkim_header {
            Some(dkim_header) => dkim_header,
            None => return Err(VerificationError::MissingDkimHeader),
        };

        let public_key = PublicKey::load(&header.selector, &header.sdid).unwrap();
        self.verify_with_public_key(&public_key)
    }

    /// Verify the mail using an existing public key (does not use the DNS).
    pub fn verify_with_public_key(&self, public_key: &PublicKey) -> Result<(), VerificationError> {
        use rsa::{PublicKey, RSAPublicKey};

        let header = match &self.dkim_header {
            Some(dkim_header) => dkim_header,
            None => return Err(VerificationError::MissingDkimHeader),
        };

        let body = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => canonicalize_body_relaxed(
                string_tools::get_all_after(self.raw, "\r\n\r\n").to_string(),
            ),
            CanonicalizationType::Simple => {
                canonicalize_body_simple(string_tools::get_all_after(self.raw, "\r\n\r\n"))
                    .to_string()
            }
        };

        let body_hash = body_hash_sha256(&body);

        if body_hash != header.body_hash {
            return Err(VerificationError::BodyHashesDontMatch);
        }

        let headers = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => {
                canonicalize_headers_relaxed(&self.parsed.0, &header.signed_headers)
            }
            CanonicalizationType::Simple => {
                canonicalize_headers_simple(&self.parsed.0, &header.signed_headers)
            }
        };

        println!(
            "\x1B[33m{:?}\x1B[0m",
            (&headers, &header.original.as_ref().unwrap())
        );
        let data_hash = data_hash_sha256(&headers, &header.original.as_ref().unwrap());

        let public_key = RSAPublicKey::from_pkcs8(&public_key.key.as_ref().unwrap()).unwrap();
        public_key.verify(
            rsa::PaddingScheme::PKCS1v15Sign {
                hash: Some(rsa::hash::Hash::SHA2_256),
            },
            &data_hash,
            &header.signature,
        )?;

        Ok(())
    }

    /// Sign the mail using a private key and an incomplete (without body_hash and signature) dkim header.
    pub fn sign(
        &mut self,
        mut header: DkimHeader,
        private_key: &rsa::RSAPrivateKey,
    ) -> Result<String, VerificationError> {
        let body = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => canonicalize_body_relaxed(
                string_tools::get_all_after(self.raw, "\r\n\r\n").to_string(),
            ),
            CanonicalizationType::Simple => {
                canonicalize_body_simple(string_tools::get_all_after(self.raw, "\r\n\r\n"))
                    .to_string()
            }
        };

        let body_hash = body_hash_sha256(&body);
        header.body_hash = body_hash;

        let headers = match header.canonicalization.0 {
            CanonicalizationType::Relaxed => {
                canonicalize_headers_relaxed(&self.parsed.0, &header.signed_headers)
            }
            CanonicalizationType::Simple => {
                canonicalize_headers_simple(&self.parsed.0, &header.signed_headers)
            }
        };
        let data_hash = data_hash_sha256(&headers, &header.to_string()); // TODO algo match
        println!("\x1B[32m{:?}\x1B[0m", (&headers, &header.to_string()));

        // TODO SHA1
        let signature = match private_key.sign(
            rsa::PaddingScheme::PKCS1v15Sign {
                hash: Some(rsa::hash::Hash::SHA2_256),
            },
            &data_hash,
        ) {
            Ok(signature) => signature,
            Err(error) => return Err(VerificationError::FailedSigning(error)),
        };
        header.signature = signature;

        let mut mail = self.raw.to_string();
        let header = header.to_string();
        let idx = mail
            .find("\r\n\r\n")
            .map(|i| i + 2)
            .unwrap_or_else(|| mail.len());
        mail.insert_str(idx, &header);
        mail.insert_str(idx + header.len(), "\r\n");

        Ok(mail)
    }
}

impl<'a> TryFrom<&'a str> for Email<'a> {
    type Error = ();

    fn try_from(email: &'a str) -> Result<Email, Self::Error> {
        let mut dkim_header = None;
        let (headers, body) = parse_message_with_separators(email.as_bytes())?;

        let headers: Vec<(&str, &str, &str)> = headers
            .iter()
            .filter_map(|(n, s, v)| {
                if let (Ok(name), Ok(separator), Ok(value)) = (std::str::from_utf8(n), std::str::from_utf8(s), std::str::from_utf8(v)) {
                    Some((name, separator, value))
                } else {
                    None
                }
            })
            .collect();

        let body = body.map(|b| std::str::from_utf8(b).ok()).flatten();

        for (name, _separator, value) in headers.iter() {
            if unicase::eq_ascii(*name, "DKIM-Signature") {
                match DkimHeader::try_from(*value) {
                    Ok(header) => dkim_header = Some(header),
                    Err(e) => println!("Can't parse DKIM header {:?}", e),
                }
                break;
            }
        }

        Ok(Email {
            raw: email,
            dkim_header,
            parsed: (headers, body),
        })
    }
}

#[test]
fn test_signing() {
    let mail = "Received: by mail-oi1-f177.google.com with SMTP id e4so8660662oib.1\r\n        for <mubelotix@mubelotix.dev>; Tue, 30 Jun 2020 01:43:28 -0700 (PDT)\r\nX-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=1e100.net; s=20161025;\r\n        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;\r\n        bh=5NNwu8gdOD3ZoZD58FM4gy7PeYn+BudAJmLL+5Moe58=;\r\n        b=SEIL6qJEGH/+sVou4i84kC4vEEsLShYrmKLAlM/7V1fIIbpyQWDRpehMKnlGFKmTCx\r\n         Mz1NijW6tbjDJ+1eF3aE/MNSzhim2eO4JmcK5kZ4vlZzzPWE+GacZqc3QNtAufgA/EqP\r\n         eWTuFSPtSY2vHJdRX21vq8WpP31KdG0JKcv3ZykDqH0y1dAM1sAGR3Gmrcyu+HGA9Ug5\r\n         BrYx1ZPyjYOtlXEiGqaKRsrBlB5P42n2aU0TwZYrEVi9N5TULM4bS+bLtP3FmxP7uIP2\r\n         ZKuFKbcTTveG3+DaaOE7HK/dHXWXZZC9RaS/yzGettgXiwmaAENcONpTwg1jD70DU5a9\r\n         DYHg==\r\nX-Gm-Message-State: AOAM533sOvLV7q5oj9SIWatwQ3kCiOgSZHBhJb0R93ImzSZav4QObpV2\r\n        pLSheyz34dtdedvMg8G3go4HsIP3ytqkN8f9j+ZTvFkx\r\nX-Google-Smtp-Source: ABdhPJzLJRsIQigY2u6fwn04UxksGTqbklM5igDK5fVI2kljDUPeTOPWxkM4IEUQpRb6Ciacz58Kj9Dqy61/LiiyDyA=\r\nX-Received: by 2002:aca:d681:: with SMTP id n123mr15403808oig.82.1593506599851;\r\n Tue, 30 Jun 2020 01:43:19 -0700 (PDT)\r\nMIME-Version: 1.0\r\nFrom: Mubelotix <mubelotix@gmail.com>\r\nDate: Tue, 30 Jun 2020 10:43:08 +0200\r\nMessage-ID: <CANc=2UXAvRBx-A7SP9JWm=pby29s_zdFvfMDUprZ+PN_8XuO+w@mail.gmail.com>\r\nSubject: Test email\r\nTo: mubelotix@mubelotix.dev\r\nContent-Type: multipart/alternative; boundary=\"000000000000d4d95805a9492a3c\"\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nTest body\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">Test body</div>\r\n\r\n--000000000000d4d95805a9492a3c--";
    let mut mail = Email::try_from(mail).unwrap();

    let key = base64::decode("MIIEowIBAAKCAQEAgxoGICfYbPE2Z75oNqCxt559UcIOBuh6RmvIrAWSIgGfFHGFiksNS/uRNOM+JAHh7UbHZtCdT5nYpNuIFboOH8TxGVw58D3dFoi97llInbHpuxcQMmVErHiEZ/5rWtCKjBE851EFU4G/1YwR+PsO7/lB5+VnU3yb0s4YcbalsY+5IKIO/ocVXBaWqu471hGAPs4GyziuZ/I40xd5N2qi5Ws9uWOnJ/NFeuKCK+l7jOY0catqheft95CIVPR0d5ihuM1bRjS/mOKhDlj/ru8emmaCzeqToUshl8LT4HZ3YVhFiM1NEj7OYDcQibIFd61ENNHc21+TOwLq3pvSZN96vwIDAQABAoIBAQCAzyXrnBqZ11m0DrGH0tUp6w+IL9jmUq4o2Ke+1G5i+SLazDr/yIPU/uQJiag5apwXLG6ohxm45xijyYpohnhwIGkemK3YbH/4Lvwl3hVp0y8pghyI11Tk/DhjkObbwIAP5LPpNoK8LIRWBZx2+/0OLOHjPVMLBSh4s8PynhkoXfT1ej3PGh29SWr0fntxwR1O3dwxq5zD9xUL4h7ngT796YOr7C26z4rS9znwvR0jdA7bIrRHF/XKHFq6dLgu7USzfP+64YKPqfv/Kw1NmA04li5+2Yu3CPL+Qf7Wqi5AvxzlQ45IcVdQeD9FizUcfREKQXTE6QSQLomWspy6H/W5AoGBAOIMCbPcUiiDgigob/8z2DkWiRggyY9yOxZHl05KDe10GOdSs567wacB1RVonZf2iwmTyBQRePrWiamzF0HCrPhF5vOx9RgNiz6PdDr6+i5w8uIXcNbieqG6tI0hlkXUZcOhu3778lLwOyw4hcdqsZK30UAmPriXRn50skgnxtwTAoGBAJR5QFtBaI3sn+2waSx8xTPuS3bR37cespYwxzr6h3McfGPnpfrOTSX3kDbVHoztL1N4TGb1c8TMvb67X9ls81AKP6J0tFPxPp4PJeuicDrJlnVqzDcTYAvfDjtzs/PBoszBfECkq6NHXq1ozG7fp8ekxf+Fug5i+7Su6fWw9SQlAoGAMcOsrygl/j1VfjnIzko/o/HOJL2zIh1n3LPOH7I19rzEbsjKOnvjWj0RCDGL4FSqr2UVezWNiMuKaw2+ZP/SzKW2/peC+dShfxhd4k42ndrH3faDJQufK9PKw/dM+fqUnMkSWhZldtTkcgvPh+N5TG+jZZgF3uWO43AVf8UiBnkCgYBLjeBID+Lqxg0kYW9D6kJYCN1yG57iisaKU0wvISooU8ig9lKqbK0psu86V/1x7Yj1yvPmOOWushmko6lE9YJjqrNzMjxJsywQNtkvLbw6zja4jZ5aMIvhvqJ5comSc2krFRLrumB1eG4fhILzsPCqUZlITH6/r3MzIQeBtYkp2QKBgDkgpa0c+ep3020iOIjFzE9in2reyAj5Kvwh1li8TGrndh3pj4OL7+Qp4Dl0ndetcB+PoMN627haxbMkQMU3+yfBJH/lLWzP/o8DFuqlCC1YniUpof0G0gJsMZR/+v4FjBnrB4guXbmC7emQ/EZ9mybnc+ilN9vn6okAZ9zsGxTk").unwrap();
    let key = rsa::RSAPrivateKey::from_pkcs1(&key).unwrap();

    let mail = mail
        .sign(
            DkimHeader::new("mubelotix.dev".to_string(), "common".to_string()),
            &key,
        )
        .unwrap();
    let mail = Email::try_from(mail.as_str()).unwrap();

    let key = base64::decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgxoGICfYbPE2Z75oNqCxt559UcIOBuh6RmvIrAWSIgGfFHGFiksNS/uRNOM+JAHh7UbHZtCdT5nYpNuIFboOH8TxGVw58D3dFoi97llInbHpuxcQMmVErHiEZ/5rWtCKjBE851EFU4G/1YwR+PsO7/lB5+VnU3yb0s4YcbalsY+5IKIO/ocVXBaWqu471hGAPs4GyziuZ/I40xd5N2qi5Ws9uWOnJ/NFeuKCK+l7jOY0catqheft95CIVPR0d5ihuM1bRjS/mOKhDlj/ru8emmaCzeqToUshl8LT4HZ3YVhFiM1NEj7OYDcQibIFd61ENNHc21+TOwLq3pvSZN96vwIDAQAB").unwrap();
    mail.verify_with_public_key(&PublicKey::new(
        false,
        true,
        false,
        false,
        String::from("rsa"),
        None,
        Some(key),
    ))
    .unwrap();
}

#[test]
fn test_signing_simple() {
    let mail = "Received: by mail-oi1-f177.google.com with SMTP id e4so8660662oib.1\r\n        for <mubelotix@mubelotix.dev>; Tue, 30 Jun 2020 01:43:28 -0700 (PDT)\r\nX-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=1e100.net; s=20161025;\r\n        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;\r\n        bh=5NNwu8gdOD3ZoZD58FM4gy7PeYn+BudAJmLL+5Moe58=;\r\n        b=SEIL6qJEGH/+sVou4i84kC4vEEsLShYrmKLAlM/7V1fIIbpyQWDRpehMKnlGFKmTCx\r\n         Mz1NijW6tbjDJ+1eF3aE/MNSzhim2eO4JmcK5kZ4vlZzzPWE+GacZqc3QNtAufgA/EqP\r\n         eWTuFSPtSY2vHJdRX21vq8WpP31KdG0JKcv3ZykDqH0y1dAM1sAGR3Gmrcyu+HGA9Ug5\r\n         BrYx1ZPyjYOtlXEiGqaKRsrBlB5P42n2aU0TwZYrEVi9N5TULM4bS+bLtP3FmxP7uIP2\r\n         ZKuFKbcTTveG3+DaaOE7HK/dHXWXZZC9RaS/yzGettgXiwmaAENcONpTwg1jD70DU5a9\r\n         DYHg==\r\nX-Gm-Message-State: AOAM533sOvLV7q5oj9SIWatwQ3kCiOgSZHBhJb0R93ImzSZav4QObpV2\r\n        pLSheyz34dtdedvMg8G3go4HsIP3ytqkN8f9j+ZTvFkx\r\nX-Google-Smtp-Source: ABdhPJzLJRsIQigY2u6fwn04UxksGTqbklM5igDK5fVI2kljDUPeTOPWxkM4IEUQpRb6Ciacz58Kj9Dqy61/LiiyDyA=\r\nX-Received: by 2002:aca:d681:: with SMTP id n123mr15403808oig.82.1593506599851;\r\n Tue, 30 Jun 2020 01:43:19 -0700 (PDT)\r\nMIME-Version: 1.0\r\nFrom: Mubelotix <mubelotix@gmail.com>\r\nDate: Tue, 30 Jun 2020 10:43:08 +0200\r\nMessage-ID: <CANc=2UXAvRBx-A7SP9JWm=pby29s_zdFvfMDUprZ+PN_8XuO+w@mail.gmail.com>\r\nSubject: Test email\r\nTo: mubelotix@mubelotix.dev\r\nContent-Type: multipart/alternative; boundary=\"000000000000d4d95805a9492a3c\"\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nTest body\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">Test body</div>\r\n\r\n--000000000000d4d95805a9492a3c--";
    let mut mail = Email::try_from(mail).unwrap();

    let key = base64::decode("MIIEowIBAAKCAQEAgxoGICfYbPE2Z75oNqCxt559UcIOBuh6RmvIrAWSIgGfFHGFiksNS/uRNOM+JAHh7UbHZtCdT5nYpNuIFboOH8TxGVw58D3dFoi97llInbHpuxcQMmVErHiEZ/5rWtCKjBE851EFU4G/1YwR+PsO7/lB5+VnU3yb0s4YcbalsY+5IKIO/ocVXBaWqu471hGAPs4GyziuZ/I40xd5N2qi5Ws9uWOnJ/NFeuKCK+l7jOY0catqheft95CIVPR0d5ihuM1bRjS/mOKhDlj/ru8emmaCzeqToUshl8LT4HZ3YVhFiM1NEj7OYDcQibIFd61ENNHc21+TOwLq3pvSZN96vwIDAQABAoIBAQCAzyXrnBqZ11m0DrGH0tUp6w+IL9jmUq4o2Ke+1G5i+SLazDr/yIPU/uQJiag5apwXLG6ohxm45xijyYpohnhwIGkemK3YbH/4Lvwl3hVp0y8pghyI11Tk/DhjkObbwIAP5LPpNoK8LIRWBZx2+/0OLOHjPVMLBSh4s8PynhkoXfT1ej3PGh29SWr0fntxwR1O3dwxq5zD9xUL4h7ngT796YOr7C26z4rS9znwvR0jdA7bIrRHF/XKHFq6dLgu7USzfP+64YKPqfv/Kw1NmA04li5+2Yu3CPL+Qf7Wqi5AvxzlQ45IcVdQeD9FizUcfREKQXTE6QSQLomWspy6H/W5AoGBAOIMCbPcUiiDgigob/8z2DkWiRggyY9yOxZHl05KDe10GOdSs567wacB1RVonZf2iwmTyBQRePrWiamzF0HCrPhF5vOx9RgNiz6PdDr6+i5w8uIXcNbieqG6tI0hlkXUZcOhu3778lLwOyw4hcdqsZK30UAmPriXRn50skgnxtwTAoGBAJR5QFtBaI3sn+2waSx8xTPuS3bR37cespYwxzr6h3McfGPnpfrOTSX3kDbVHoztL1N4TGb1c8TMvb67X9ls81AKP6J0tFPxPp4PJeuicDrJlnVqzDcTYAvfDjtzs/PBoszBfECkq6NHXq1ozG7fp8ekxf+Fug5i+7Su6fWw9SQlAoGAMcOsrygl/j1VfjnIzko/o/HOJL2zIh1n3LPOH7I19rzEbsjKOnvjWj0RCDGL4FSqr2UVezWNiMuKaw2+ZP/SzKW2/peC+dShfxhd4k42ndrH3faDJQufK9PKw/dM+fqUnMkSWhZldtTkcgvPh+N5TG+jZZgF3uWO43AVf8UiBnkCgYBLjeBID+Lqxg0kYW9D6kJYCN1yG57iisaKU0wvISooU8ig9lKqbK0psu86V/1x7Yj1yvPmOOWushmko6lE9YJjqrNzMjxJsywQNtkvLbw6zja4jZ5aMIvhvqJ5comSc2krFRLrumB1eG4fhILzsPCqUZlITH6/r3MzIQeBtYkp2QKBgDkgpa0c+ep3020iOIjFzE9in2reyAj5Kvwh1li8TGrndh3pj4OL7+Qp4Dl0ndetcB+PoMN627haxbMkQMU3+yfBJH/lLWzP/o8DFuqlCC1YniUpof0G0gJsMZR/+v4FjBnrB4guXbmC7emQ/EZ9mybnc+ilN9vn6okAZ9zsGxTk").unwrap();
    let key = rsa::RSAPrivateKey::from_pkcs1(&key).unwrap();

    let mail = mail
        .sign(
            DkimHeader::new("mubelotix.dev".to_string(), "common".to_string())
                .with_canonicalization((
                    CanonicalizationType::Simple,
                    CanonicalizationType::Simple,
                )),
            &key,
        )
        .unwrap();
    let mail = Email::try_from(mail.as_str()).unwrap();

    let key = base64::decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgxoGICfYbPE2Z75oNqCxt559UcIOBuh6RmvIrAWSIgGfFHGFiksNS/uRNOM+JAHh7UbHZtCdT5nYpNuIFboOH8TxGVw58D3dFoi97llInbHpuxcQMmVErHiEZ/5rWtCKjBE851EFU4G/1YwR+PsO7/lB5+VnU3yb0s4YcbalsY+5IKIO/ocVXBaWqu471hGAPs4GyziuZ/I40xd5N2qi5Ws9uWOnJ/NFeuKCK+l7jOY0catqheft95CIVPR0d5ihuM1bRjS/mOKhDlj/ru8emmaCzeqToUshl8LT4HZ3YVhFiM1NEj7OYDcQibIFd61ENNHc21+TOwLq3pvSZN96vwIDAQAB").unwrap();
    mail.verify_with_public_key(&PublicKey::new(
        false,
        true,
        false,
        false,
        String::from("rsa"),
        None,
        Some(key),
    ))
    .unwrap();
}
