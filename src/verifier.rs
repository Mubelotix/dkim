pub use crate::*;

pub fn verify(hash: &[u8], signature: &[u8]) -> bool {
    use ring::{rand, signature};

    use base64::decode;
    
    let key = decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviPGBk4ZB64UfSqWyAicdR7lodhytae+EYRQVtKDhM+1mXjEqRtP/pDT3sBhazkmA48n2k5NJUyMEoO8nc2r6sUA+/Dom5jRBZp6qDKJOwjJ5R/OpHamlRG+YRJQqRtqEgSiJWG7h7efGYWmh4URhFM9k9+rmG/CwCgwx7Et+c8OMlngaLl04/bPmfpjdEyLWyNimk761CX6KymzYiRDNz1MOJOJ7OzFaS4PFbVLn0m5mf0HVNtBpPwWuCNvaFVflUYxEyblbB6h/oWOPGbzoSgtRA47SHV53SwZjIsVpbq4LxUW9IxAEwYzGcSgZ4n5Q8X8TndowsDUzoccPFGhdwIDAQAB").unwrap();
    
    let public_key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key);
    public_key.verify(hash, &signature)
        .map_err(|e| println!("{:?}",e));
    
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