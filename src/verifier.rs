pub fn verify(hash: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    use rsa::{RSAPublicKey, PublicKey};
    
    let public_key = RSAPublicKey::from_pkcs8(&public_key).unwrap();
    public_key.verify(rsa::PaddingScheme::PKCS1v15Sign{hash: Some(rsa::hash::Hash::SHA2_256)}, &hash, signature).is_ok()
}