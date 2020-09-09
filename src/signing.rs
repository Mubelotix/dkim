use crate::dkim::{Header, CanonicalizationType, SigningAlgorithm};
use crate::{canonicalization::*, hash::*};
use crate::parsing::parse_mail;

pub type MAIL<'a> = (&'a [(&'a str, &'a str)], &'a str);

#[derive(Debug)]
pub enum SigningError {
    InvalidMail,
    InvalidSpecifiedLenght,
    FailedSigning(rsa::errors::Error)
}

/// Parse a mail and create a DKIM-Signature header.  
/// You can avoid the parsing performance cost by using the [get_signature_parsed]() function.
pub fn get_signature<'a, 'b>(raw_mail: &'a str, header: Header<'b>, private_key: &'a rsa::RSAPrivateKey) -> Result<Header<'b>, SigningError> {
    let (headers, body) = parse_mail(raw_mail).map_err(|()| SigningError::InvalidMail)?;

    get_signature_parsed((&headers, body), header, private_key)
}

/// Create a DKIM-Signature header for a mail.  
pub fn get_signature_parsed<'a, 'b>(parsed_mail: MAIL<'a>, mut header: Header<'b>, private_key: &'a rsa::RSAPrivateKey) -> Result<Header<'b>, SigningError> {
    // canonicalization
    let owned_body;
    let mut body = match header.canonicalization.0 {
        CanonicalizationType::Relaxed => {
            owned_body = canonicalize_body_relaxed(
                parsed_mail.1.to_string()
            );
            &owned_body
        },
        CanonicalizationType::Simple => {
            canonicalize_body_simple(parsed_mail.1)
        }
    };
    let headers = match header.canonicalization.0 {
        CanonicalizationType::Relaxed => {
            canonicalize_headers_relaxed(&parsed_mail.0, &header.signed_headers)
        }
        CanonicalizationType::Simple => {
            canonicalize_headers_simple(&parsed_mail.0, &header.signed_headers)
        }
    };
    if let Some(lenght) = header.body_lenght {
        if body.get(lenght..).is_some() {
            body = body.get(lenght..).unwrap()
        } else {
            return Err(SigningError::InvalidSpecifiedLenght);
        }
    }

    // hashing
    let body_hash = match header.algorithm {
        SigningAlgorithm::RsaSha1 => body_hash_sha1(&body),
        SigningAlgorithm::RsaSha256 => body_hash_sha256(&body),
    };
    header.body_hash = body_hash;
    let data_hash = match header.algorithm {
        SigningAlgorithm::RsaSha1 => data_hash_sha1(&headers, &header.to_string()),
        SigningAlgorithm::RsaSha256 => data_hash_sha256(&headers, &header.to_string()),
    };

    // signing
    let signature = match private_key.sign(
        rsa::PaddingScheme::PKCS1v15Sign {
            hash: Some(match header.algorithm {
                SigningAlgorithm::RsaSha1 => rsa::hash::Hash::SHA1,
                SigningAlgorithm::RsaSha256 => rsa::hash::Hash::SHA2_256,
            }),
        },
        &data_hash,
    ) {
        Ok(signature) => signature,
        Err(error) => return Err(SigningError::FailedSigning(error)),
    };
    header.signature = signature;

    Ok(header)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tests_get_signature() {
        let key = base64::decode("MIIEowIBAAKCAQEAgxoGICfYbPE2Z75oNqCxt559UcIOBuh6RmvIrAWSIgGfFHGFiksNS/uRNOM+JAHh7UbHZtCdT5nYpNuIFboOH8TxGVw58D3dFoi97llInbHpuxcQMmVErHiEZ/5rWtCKjBE851EFU4G/1YwR+PsO7/lB5+VnU3yb0s4YcbalsY+5IKIO/ocVXBaWqu471hGAPs4GyziuZ/I40xd5N2qi5Ws9uWOnJ/NFeuKCK+l7jOY0catqheft95CIVPR0d5ihuM1bRjS/mOKhDlj/ru8emmaCzeqToUshl8LT4HZ3YVhFiM1NEj7OYDcQibIFd61ENNHc21+TOwLq3pvSZN96vwIDAQABAoIBAQCAzyXrnBqZ11m0DrGH0tUp6w+IL9jmUq4o2Ke+1G5i+SLazDr/yIPU/uQJiag5apwXLG6ohxm45xijyYpohnhwIGkemK3YbH/4Lvwl3hVp0y8pghyI11Tk/DhjkObbwIAP5LPpNoK8LIRWBZx2+/0OLOHjPVMLBSh4s8PynhkoXfT1ej3PGh29SWr0fntxwR1O3dwxq5zD9xUL4h7ngT796YOr7C26z4rS9znwvR0jdA7bIrRHF/XKHFq6dLgu7USzfP+64YKPqfv/Kw1NmA04li5+2Yu3CPL+Qf7Wqi5AvxzlQ45IcVdQeD9FizUcfREKQXTE6QSQLomWspy6H/W5AoGBAOIMCbPcUiiDgigob/8z2DkWiRggyY9yOxZHl05KDe10GOdSs567wacB1RVonZf2iwmTyBQRePrWiamzF0HCrPhF5vOx9RgNiz6PdDr6+i5w8uIXcNbieqG6tI0hlkXUZcOhu3778lLwOyw4hcdqsZK30UAmPriXRn50skgnxtwTAoGBAJR5QFtBaI3sn+2waSx8xTPuS3bR37cespYwxzr6h3McfGPnpfrOTSX3kDbVHoztL1N4TGb1c8TMvb67X9ls81AKP6J0tFPxPp4PJeuicDrJlnVqzDcTYAvfDjtzs/PBoszBfECkq6NHXq1ozG7fp8ekxf+Fug5i+7Su6fWw9SQlAoGAMcOsrygl/j1VfjnIzko/o/HOJL2zIh1n3LPOH7I19rzEbsjKOnvjWj0RCDGL4FSqr2UVezWNiMuKaw2+ZP/SzKW2/peC+dShfxhd4k42ndrH3faDJQufK9PKw/dM+fqUnMkSWhZldtTkcgvPh+N5TG+jZZgF3uWO43AVf8UiBnkCgYBLjeBID+Lqxg0kYW9D6kJYCN1yG57iisaKU0wvISooU8ig9lKqbK0psu86V/1x7Yj1yvPmOOWushmko6lE9YJjqrNzMjxJsywQNtkvLbw6zja4jZ5aMIvhvqJ5comSc2krFRLrumB1eG4fhILzsPCqUZlITH6/r3MzIQeBtYkp2QKBgDkgpa0c+ep3020iOIjFzE9in2reyAj5Kvwh1li8TGrndh3pj4OL7+Qp4Dl0ndetcB+PoMN627haxbMkQMU3+yfBJH/lLWzP/o8DFuqlCC1YniUpof0G0gJsMZR/+v4FjBnrB4guXbmC7emQ/EZ9mybnc+ilN9vn6okAZ9zsGxTk").unwrap();
        let key = rsa::RSAPrivateKey::from_pkcs1(&key).unwrap();

        get_signature("Received: by mail-oi1-f177.google.com with SMTP id e4so8660662oib.1\r\n        for <mubelotix@mubelotix.dev>; Tue, 30 Jun 2020 01:43:28 -0700 (PDT)\r\nX-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=1e100.net; s=20161025;\r\n        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;\r\n        bh=5NNwu8gdOD3ZoZD58FM4gy7PeYn+BudAJmLL+5Moe58=;\r\n        b=SEIL6qJEGH/+sVou4i84kC4vEEsLShYrmKLAlM/7V1fIIbpyQWDRpehMKnlGFKmTCx\r\n         Mz1NijW6tbjDJ+1eF3aE/MNSzhim2eO4JmcK5kZ4vlZzzPWE+GacZqc3QNtAufgA/EqP\r\n         eWTuFSPtSY2vHJdRX21vq8WpP31KdG0JKcv3ZykDqH0y1dAM1sAGR3Gmrcyu+HGA9Ug5\r\n         BrYx1ZPyjYOtlXEiGqaKRsrBlB5P42n2aU0TwZYrEVi9N5TULM4bS+bLtP3FmxP7uIP2\r\n         ZKuFKbcTTveG3+DaaOE7HK/dHXWXZZC9RaS/yzGettgXiwmaAENcONpTwg1jD70DU5a9\r\n         DYHg==\r\nX-Gm-Message-State: AOAM533sOvLV7q5oj9SIWatwQ3kCiOgSZHBhJb0R93ImzSZav4QObpV2\r\n        pLSheyz34dtdedvMg8G3go4HsIP3ytqkN8f9j+ZTvFkx\r\nX-Google-Smtp-Source: ABdhPJzLJRsIQigY2u6fwn04UxksGTqbklM5igDK5fVI2kljDUPeTOPWxkM4IEUQpRb6Ciacz58Kj9Dqy61/LiiyDyA=\r\nX-Received: by 2002:aca:d681:: with SMTP id n123mr15403808oig.82.1593506599851;\r\n Tue, 30 Jun 2020 01:43:19 -0700 (PDT)\r\nMIME-Version: 1.0\r\nFrom: Mubelotix <mubelotix@gmail.com>\r\nDate: Tue, 30 Jun 2020 10:43:08 +0200\r\nMessage-ID: <CANc=2UXAvRBx-A7SP9JWm=pby29s_zdFvfMDUprZ+PN_8XuO+w@mail.gmail.com>\r\nSubject: Test email\r\nTo: mubelotix@mubelotix.dev\r\nContent-Type: multipart/alternative; boundary=\"000000000000d4d95805a9492a3c\"\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nTest body\r\n\r\n--000000000000d4d95805a9492a3c\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">Test body</div>\r\n\r\n--000000000000d4d95805a9492a3c--", Header::new("mubelotix.dev", "common"), &key).unwrap();
    }
}