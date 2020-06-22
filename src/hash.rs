pub fn hash_sha1() {

}

pub fn hash_sha256(data: &str) -> Vec<u8> {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}