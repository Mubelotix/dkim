use crate::*;

pub fn get_dkim_header(mail: &str) {
    unimplemented!()
}

pub fn verify(hash: &[u8], signature: &[u8]) -> bool {
    use ring::{rand, signature};
    use rsa::RSAPublicKey;
    use rsa::PublicKey;
    use base64::{decode, encode};
    
    let key = decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviPGBk4ZB64UfSqWyAicdR7lodhytae+EYRQVtKDhM+1mXjEqRtP/pDT3sBhazkmA48n2k5NJUyMEoO8nc2r6sUA+/Dom5jRBZp6qDKJOwjJ5R/OpHamlRG+YRJQqRtqEgSiJWG7h7efGYWmh4URhFM9k9+rmG/CwCgwx7Et+c8OMlngaLl04/bPmfpjdEyLWyNimk761CX6KymzYiRDNz1MOJOJ7OzFaS4PFbVLn0m5mf0HVNtBpPwWuCNvaFVflUYxEyblbB6h/oWOPGbzoSgtRA47SHV53SwZjIsVpbq4LxUW9IxAEwYzGcSgZ4n5Q8X8TndowsDUzoccPFGhdwIDAQAB").unwrap();

    //let rsa_key = RSAPublicKey::new(rsa::BigUint::from_bytes_be(&key), 65537u32.into()).unwrap();
    let file_content = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviPGBk4ZB64UfSqWyAicdR7lodhytae+EYRQVtKDhM+1mXjEqRtP/pDT3sBhazkmA48n2k5NJUyMEoO8nc2r6sUA+/Dom5jRBZp6qDKJOwjJ5R/OpHamlRG+YRJQqRtqEgSiJWG7h7efGYWmh4URhFM9k9+rmG/CwCgwx7Et+c8OMlngaLl04/bPmfpjdEyLWyNimk761CX6KymzYiRDNz1MOJOJ7OzFaS4PFbVLn0m5mf0HVNtBpPwWuCNvaFVflUYxEyblbB6h/oWOPGbzoSgtRA47SHV53SwZjIsVpbq4LxUW9IxAEwYzGcSgZ4n5Q8X8TndowsDUzoccPFGhdwIDAQAB
-----END PUBLIC KEY-----
"#;

    let der_encoded = file_content
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");


    let rsa_key = RSAPublicKey::from_pkcs8(&der_bytes).unwrap();

    println!("\nkey: {}\nhash: {}\nsignature: {}", encode(key), encode(hash), encode(signature));
    rsa_key.verify(rsa::PaddingScheme::PKCS1v15Sign{hash: Some(rsa::hash::Hash::SHA2_256)}, &hash, signature).unwrap();
    
    true
}

pub struct Verifier<'a> {
    v: usize,
    a: SigningAlgorithm,
    b: &'a str,
    bh: &'a str,
    c: (MessageCanonicalization, MessageCanonicalization),
    d: &'a str,
    h: Vec<&'a str>,
    i: &'a str,
    l: usize,
    q: &'a str,
}