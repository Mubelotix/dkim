pub fn hash_sha1() {

}

pub fn body_hash_sha256(data: &str) -> Vec<u8> {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn data_hash_sha256(headers: &str, dkim_header: &str) -> Vec<u8> {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(headers);
    hasher.update(dkim_header);
    hasher.finalize().to_vec()
}