use crate::*;

pub fn get_dkim_header(mail: &str) {
    unimplemented!()
}

pub fn verify(hash: &[u8], signature: &[u8]) -> bool {
    use rsa::RSAPublicKey;
    use rsa::PublicKey;
    
    let der_bytes = base64::decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviPGBk4ZB64UfSqWyAicdR7lodhytae+EYRQVtKDhM+1mXjEqRtP/pDT3sBhazkmA48n2k5NJUyMEoO8nc2r6sUA+/Dom5jRBZp6qDKJOwjJ5R/OpHamlRG+YRJQqRtqEgSiJWG7h7efGYWmh4URhFM9k9+rmG/CwCgwx7Et+c8OMlngaLl04/bPmfpjdEyLWyNimk761CX6KymzYiRDNz1MOJOJ7OzFaS4PFbVLn0m5mf0HVNtBpPwWuCNvaFVflUYxEyblbB6h/oWOPGbzoSgtRA47SHV53SwZjIsVpbq4LxUW9IxAEwYzGcSgZ4n5Q8X8TndowsDUzoccPFGhdwIDAQAB").unwrap();

    let rsa_key = RSAPublicKey::from_pkcs8(&der_bytes).unwrap();

    rsa_key.verify(rsa::PaddingScheme::PKCS1v15Sign{hash: Some(rsa::hash::Hash::SHA2_256)}, &hash, signature).unwrap();
    
    true
}